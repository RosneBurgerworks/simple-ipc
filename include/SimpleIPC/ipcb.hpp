/*
 * ipcb.hpp
 *
 *  Created on: Feb 5, 2017
 *      Author: nullifiedcat
 */

#pragma once

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <functional>
#include <thread>
#include <condition_variable>
#include <mutex>

#include "util.hpp"
#include "cmp.hpp"

namespace cat_ipc
{
constexpr unsigned char max_peers     = UCHAR_MAX;
constexpr unsigned int command_buffer = max_peers * 2;
constexpr unsigned int pool_size      = command_buffer * 4096;
constexpr unsigned int command_data   = 64;

struct PeerData
{
    bool free;
    time_t heartbeat;
    pid_t pid;
    unsigned long starttime;
};

struct Command
{
    unsigned int command_number;
    int target_peer;
    int sender;
    unsigned long payload_offset;
    unsigned int payload_size;
    unsigned int cmd_type;
    unsigned char cmd_data[command_data];
};

class InterprocessMutex
{
public:
    explicit InterprocessMutex(const char *name) : name(name)
    {
        sem = sem_open(name, O_CREAT, 0666, 1); // 0666 permissions allow all users to open the semaphore
        if (sem == SEM_FAILED)
        {
            throw std::runtime_error("Error creating semaphore");
        }
    }

    ~InterprocessMutex()
    {
        sem_close(sem);
        sem_unlink(name);
    }

    void lock()
    {
        sem_wait(sem);
    }

    void unlock()
    {
        sem_post(sem);
    }

private:
    sem_t *sem;
    const char *name;
};

class SharedMemory
{
public:
    SharedMemory(const char *name, std::size_t size, bool isManager) : size(size), name(name), isManager(isManager)
    {
        if (isManager)
        {
            shm_unlink(name); // Ensure it doesn't exist

            fd = shm_open(name, O_CREAT | O_RDWR, 0666);
            if (fd == -1)
            {
                throw std::runtime_error("Error creating shared memory");
            }

            if (ftruncate(fd, size) == -1)
            {
                throw std::runtime_error("Error setting shared memory size");
            }
        }
        else
        {
            fd = shm_open(name, O_RDWR, 0666);
            if (fd == -1)
            {
                throw std::runtime_error("Error opening existing shared memory");
            }
        }

        data = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (data == MAP_FAILED)
        {
            throw std::runtime_error("Error mapping shared memory");
        }
    }

    ~SharedMemory()
    {
        munmap(data, size);
        close(fd);
        if (isManager)
        {
            shm_unlink(name);
        }
    }

    void *getData()
    {
        return data;
    }

private:
    int fd;
    void *data;
    std::size_t size;
    const char *name;
    bool isManager;
};

// S = struct for global data
// U = struct for peer data
template <typename S, typename U> struct IPCMemory
{
    static_assert(std::is_standard_layout<S>::value && std::is_trivial<S>::value, "Global data struct must be POD");
    static_assert(std::is_standard_layout<U>::value && std::is_trivial<U>::value, "Peer data struct must be POD");
    InterprocessMutex mutex;                     // IPC mutex, must be locked every time you access IPCMemory
    unsigned int peer_count{};                   // count of alive peers, managed by "manager" (server)
    unsigned long command_count{};               // last command number + 1
    PeerData peer_data[max_peers]{};             // state of each peer, managed by server
    Command commands[command_buffer]{};          // command buffer, every peer can write/read here
    std::array<unsigned char, pool_size> pool{}; // pool for storing command payloads
    S global_data;                               // some data, struct is defined by user
    std::array<U, max_peers> peer_user_data;     // some data for each peer, struct is defined by user
};

template <typename S, typename U> class Peer
{
public:
    using memory_t            = IPCMemory<S, U>;
    using CommandCallbackFn_t = std::function<void(const Command &, void *)>;

    /*
     * name: IPC file name, will be used with shm_open
     * process_old_commands: if false, peer's last_command will be set to actual last command in memory to prevent processing outdated commands
     * manager: there must be only one manager peer in memory, if the peer is manager, it allocates/deallocates shared memory
     */
    explicit Peer(std::string name, bool process_old_commands = true, bool manager = false, bool ghost = false) : name(std::move(name)), process_old_commands(process_old_commands), is_manager(manager), is_ghost(ghost)
    {
    }

    ~Peer()
    {
        shutting_down = true;
        if (heartbeat_thread.joinable())
        {
            heartbeat_thread.join();
        }

        if (is_ghost)
        {
            return;
        }

        if (memory)
        {
            std::unique_lock<InterprocessMutex> lock(memory->mutex);
            memory->peer_data[client_id].free = true;
        }
    }

    /*
     * Checks if peer has new commands to process (non-blocking)
     */
    bool HasCommands() const
    {
        return last_command != memory->command_count;
    }

    static void Heartbeat(const bool *shutting_down, PeerData *data)
    {
        while (!*shutting_down)
        {
            data->heartbeat = std::time(nullptr);
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    /*
     * Actually connects to server
     */
    void Connect()
    {
        connected = true;

        if (is_manager)
        {
            // Create shared memory
            sharedMemory = std::make_unique<SharedMemory>(name.c_str(), sizeof(memory_t), true);

            memory = static_cast<memory_t*>(sharedMemory->getData());
            new (&memory->mutex) InterprocessMutex("IPC Server");
        }
        else
        {
            // Open existing shared memory
            sharedMemory = std::make_unique<SharedMemory>(name.c_str(), sizeof(memory_t), false);
            memory = static_cast<memory_t*>(sharedMemory->getData());
        }

        pool = std::make_unique<simple_ipc::CatMemoryPool>(memory->pool.data(), pool_size);

        if (is_manager)
        {
            InitManager();
        }

        if (!is_ghost)
        {
            memory->mutex.lock();
            client_id = FirstAvailableSlot();
            StorePeerData();
            memory->mutex.unlock();
        }
        else
        {
            client_id = -1;
        }

        if (!process_old_commands)
        {
            last_command = memory->command_count;
        }

        if (!is_ghost)
        {
            heartbeat_thread = std::jthread(Heartbeat, &this->shutting_down, &memory->peer_data[client_id]);
            if (!heartbeat_thread.joinable())
            {
                throw std::runtime_error("Failed to create heartbeat thread: " + std::string(strerror(errno)));
            }
        }
    }

    /*
     * Checks every slot in memory->peer_data, throws runtime_error if there are no free slots
     */
    int FirstAvailableSlot()
    {
        for (int i = 0; i < max_peers; ++i)
        {
            if (memory->peer_data[i].free)
            {
                return i;
            }
        }

        throw std::runtime_error("No available slots");
    }

    /*
     * Returns true if the slot can be marked free
     */
    bool IsPeerDead(int id) const
    {
        return std::time(nullptr) - memory->peer_data[id].heartbeat >= 10;
    }

    /*
     * Should be called only once in a lifetime of ipc instance.
     * this function initializes memory
     */
    void InitManager()
    {
        std::memset(memory, 0, sizeof(memory_t));
        for (int i = 0; i < max_peers; ++i)
        {
            memory->peer_data[i].free = true;
        }
        pool->init();
    }

    /*
     * Marks every dead peer as free
     */
    void SweepDead()
    {
        this->memory->mutex.lock();
        memory->peer_count = 0;
        for (int i = 0; i < max_peers; ++i)
        {
            if (IsPeerDead(i))
            {
                memory->peer_data[i].free = true;
            }

            if (!memory->peer_data[i].free)
            {
                memory->peer_count++;
            }
        }
        this->memory->mutex.unlock();
    }

    /*
     * Stores data about this peer in memory
     */
    void StorePeerData()
    {
        if (is_ghost)
        {
            return;
        }

        pid_t pid = getpid();
        ProcStat stat{};
        if (!ReadStat(pid, &stat))
        {
            return;
        }

        auto &current_peer_data = memory->peer_data[client_id];

        current_peer_data.free      = false;
        current_peer_data.pid       = pid;
        current_peer_data.starttime = stat.starttime;
    }

    /*
     * A callback will be called every time peer gets a message
     * previously named: SetCallback(...)
     */
    void SetGeneralHandler(CommandCallbackFn_t new_callback)
    {
        callback = std::move(new_callback);
    }

    /*
     * Set a handler that will be fired when command with specified type will appear
     */
    void SetCommandHandler(unsigned int command_type, const CommandCallbackFn_t &handler)
    {
        auto [iterator, inserted] = callback_map.insert({ command_type, handler });

        if (!inserted)
        {
            throw std::logic_error("Single command type can't have multiple callbacks (" + std::to_string(command_type) + ")");
        }
    }

    /*
     * Processes every command with command_number higher than this peer's last_command
     */
    void ProcessCommands()
    {
        for (unsigned int i = 0; i < command_buffer; ++i)
        {
            Command &cmd = memory->commands[i];

            if (cmd.command_number <= last_command)
            {
                continue;
            }

            last_command = cmd.command_number;
            if (cmd.sender == client_id || is_ghost || (cmd.target_peer >= 0 && cmd.target_peer != client_id))
            {
                continue;
            }

            void *payload = cmd.payload_size ? pool->real_pointer<void>(reinterpret_cast<void *>(cmd.payload_offset)) : nullptr;

            if (callback)
            {
                callback(cmd, payload);
            }

            auto callback_it = callback_map.find(cmd.cmd_type);
            if (callback_it != callback_map.end())
            {
                callback_it->second(cmd, payload);
            }
        }
    }

    /*
     * Posts a command to memory, increases command_count
     */
    void SendMessage(const char *data_small, int peer_id, unsigned int command_type, const void *payload, size_t payload_size)
    {
        std::scoped_lock lock(this->memory->mutex);
        Command &cmd = memory->commands[++memory->command_count % command_buffer];
        if (cmd.payload_size)
        {
            pool->free(pool->real_pointer<void>(reinterpret_cast<void *>(cmd.payload_offset)));
            cmd.payload_offset = 0;
            cmd.payload_size   = 0;
        }

        if (data_small)
        {
            std::memcpy(cmd.cmd_data, data_small, sizeof(cmd.cmd_data));
        }

        if (payload_size)
        {
            void *block = pool->alloc(payload_size);
            std::memcpy(block, payload, payload_size);
            cmd.payload_offset = reinterpret_cast<unsigned long>(pool->pool_pointer<void>(block));
            cmd.payload_size   = payload_size;
        }
        cmd.cmd_type       = command_type;
        cmd.sender         = client_id;
        cmd.target_peer    = peer_id;
        cmd.command_number = memory->command_count;
    }

    memory_t *memory{ nullptr };
    bool connected{ false };
    int client_id{ 0 };
    const bool is_ghost{ false };
    std::shared_ptr<simple_ipc::CatMemoryPool> pool{ nullptr };

private:
    std::unique_ptr<SharedMemory> sharedMemory;
    std::unordered_map<unsigned int, CommandCallbackFn_t> callback_map{};
    unsigned long last_command{ 0 };
    CommandCallbackFn_t callback{ nullptr };
    const std::string name;
    bool process_old_commands{ true };
    const bool is_manager{ false };
    std::jthread heartbeat_thread;
    bool shutting_down{ false };
};
} // namespace cat_ipc