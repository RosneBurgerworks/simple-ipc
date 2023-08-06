/*
 * ipcb.hpp
 *
 * Created on: Feb 5, 2017
 * Author: nullifiedcat
 */

#ifndef IPCB_HPP_
#define IPCB_HPP_

#include <unistd.h>
#include <pthread.h>
#include <memory.h>
#include <unordered_map>
#include <iostream>
#include <type_traits>
#include <functional>
#include <boost/interprocess/sync/interprocess_mutex.hpp>
#include <boost/thread/mutex.hpp>
#include "util.hpp"
#include "cmp.hpp"

namespace cat_ipc {

constexpr unsigned int MAX_PEERS = 254;
constexpr unsigned int COMMAND_BUFFER = MAX_PEERS * 2;
constexpr unsigned int POOL_SIZE = COMMAND_BUFFER * 4096; // Ample space.
constexpr unsigned int COMMAND_DATA = 64; // Guaranteed space for each command

struct PeerData {
    bool free;
    time_t heartbeat;
    pid_t pid;
    unsigned long starttime;
};

struct Command {
    unsigned int command_number;
    int target_peer;
    int sender;
    unsigned long payload_offset;
    unsigned int payload_size;
    unsigned int cmd_type;
    unsigned char cmd_data[COMMAND_DATA];
};

template <typename S, typename U>
struct IPCMemory {
    static_assert(std::is_pod<S>::value, "Global data struct must be POD");
    static_assert(std::is_pod<U>::value, "Peer data struct must be POD");

    boost::interprocess::interprocess_mutex mutex;
    unsigned int peer_count;
    unsigned long command_count;
    PeerData peer_data[MAX_PEERS];
    Command commands[COMMAND_BUFFER];
    unsigned char pool[POOL_SIZE];
    S global_data;
    U peer_user_data[MAX_PEERS];
};

template <typename S, typename U>
class Peer {
public:
    typedef IPCMemory<S, U> MemoryType;

    Peer(std::string name, bool process_old_commands = true, bool manager = false, bool ghost = false)
        : name(name), process_old_commands(process_old_commands), is_manager(manager), is_ghost(ghost) {}

    ~Peer() {
        if (heartbeat_thread) {
            pthread_cancel(heartbeat_thread);
            pthread_join(heartbeat_thread, nullptr);
        }
        if (is_manager) {
            shm_unlink(name.c_str());
            munmap(memory, sizeof(MemoryType));
            return;
        }
        if (is_ghost) {
            return;
        }
        if (memory) {
            this->memory->mutex.lock();
            memory->peer_data[client_id].free = true;
            this->memory->mutex.unlock();
        }
    }

    typedef std::function<void(Command &, void *)> CommandCallbackFn;

    bool HasCommands() const {
        return (last_command != memory->command_count);
    }

    static void *Heartbeat(void *pdata) {
        auto data = reinterpret_cast<PeerData *>(pdata);
        while (true) {
            data->heartbeat = time(nullptr);
            sleep(1);
        }
        return nullptr;
    }

    void Connect() {
        connected = true;
        int old_mask = umask(0);
        int flags = O_RDWR;
        if (is_manager)
            flags |= O_CREAT;
        int fd = shm_open(name.c_str(), flags, S_IRWXU | S_IRWXG | S_IRWXO);
        if (fd == -1) {
            throw std::runtime_error("server isn't running");
        }
        ftruncate(fd, sizeof(MemoryType));
        umask(old_mask);
        memory = (MemoryType *)mmap(0, sizeof(MemoryType), PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
        close(fd);
        pool = new CatMemoryPool(&memory->pool, POOL_SIZE);
        if (is_manager) {
            InitManager();
        }
        if (!is_ghost) {
            this->memory->mutex.lock();
            client_id = FirstAvailableSlot();
            StorePeerData();
            this->memory->mutex.unlock();
        } else {
            client_id = -1;
        }
        if (!process_old_commands) {
            last_command = memory->command_count;
        }
        if (!is_ghost && pthread_create(&heartbeat_thread, nullptr, Heartbeat, &memory->peer_data[client_id]))
            throw std::runtime_error("cannot create heartbeat thread");
    }

    signed FirstAvailableSlot() {
        for (signed i = 0; i < MAX_PEERS; i++) {
            if (memory->peer_data[i].free) {
                return i;
            }
        }
        throw std::runtime_error("no available slots");
    }

    bool IsPeerDead(signed id) const {
        if (time(nullptr) - memory->peer_data[id].heartbeat >= 10)
            return true;

        return false;
    }

    void InitManager() {
        memset(memory, 0, sizeof(MemoryType));
        for (signed i = 0; i < MAX_PEERS; i++)
            memory->peer_data[i].free = true;
        pool->init();
    }

    void SweepDead() {
        this->memory->mutex.lock();
        memory->peer_count = 0;
        for (signed i = 0; i < MAX_PEERS; i++) {
            if (IsPeerDead(i)) {
                memory->peer_data[i].free = true;
            }
            if (!memory->peer_data[i].free) {
                memory->peer_count++;
            }
        }
        this->memory->mutex.unlock();
    }

    void StorePeerData() {
        if (is_ghost) {
            return;
        }
        proc_stat_s stat;
        read_stat(getpid(), &stat);
        memory->peer_data[client_id].free = false;
        memory->peer_data[client_id].pid = getpid();
        memory->peer_data[client_id].starttime = stat.starttime;
    }

    void SetGeneralHandler(CommandCallbackFn new_callback) {
        callback = new_callback;
    }

    void SetCommandHandler(unsigned int command_type, CommandCallbackFn handler) {
        if (callback_map.find(command_type) != callback_map.end()) {
            throw std::logic_error("single command type can't have multiple callbacks (" + std::to_string(command_type) + ")");
        }
        callback_map.emplace(command_type, handler);
    }

    void ProcessCommands() {
        for (unsigned i = 0; i < COMMAND_BUFFER; i++) {
            Command &cmd = memory->commands[i];
            if (cmd.command_number > last_command) {
                last_command = cmd.command_number;
                if (cmd.sender != client_id && !is_ghost && (cmd.target_peer < 0 || cmd.target_peer == client_id)) {
                    if (callback) {
                        callback(cmd, cmd.payload_size ? pool->real_pointer<void>((void *)cmd.payload_offset) : nullptr);
                    }
                    if (callback_map.find(cmd.cmd_type) != callback_map.end()) {
                        callback_map[cmd.cmd_type](cmd, cmd.payload_size ? pool->real_pointer<void>((void *)cmd.payload_offset) : nullptr);
                    }
                }
            }
        }
    }

    void SendMessage(const char *data_small, signed int peer_id, unsigned int command_type, const void *payload, size_t payload_size) {
        this->memory->mutex.lock();
        Command &cmd = memory->commands[++memory->command_count % COMMAND_BUFFER];
        if (cmd.payload_size) {
            pool->free(pool->real_pointer<void>((void *)cmd.payload_offset));
            cmd.payload_offset = 0;
            cmd.payload_size = 0;
        }
        if (data_small)
            memcpy(cmd.cmd_data, data_small, sizeof(cmd.cmd_data));
        if (payload_size) {
            void *block = pool->alloc(payload_size);
            memcpy(block, payload, payload_size);
            cmd.payload_offset = (unsigned long)pool->pool_pointer<void>(block);
            cmd.payload_size = payload_size;
        }
        cmd.cmd_type = command_type;
        cmd.sender = client_id;
        cmd.target_peer = peer_id;
        cmd.command_number = memory->command_count;
        this->memory->mutex.unlock();
    }

    std::unordered_map<unsigned int, CommandCallbackFn> callback_map{};
    bool connected{ false };
    signed int client_id{ 0 };
    unsigned long last_command{ 0 };
    CommandCallbackFn callback{ nullptr };
    CatMemoryPool *pool{ nullptr };
    const std::string name;
    bool process_old_commands{ true };
    MemoryType *memory{ nullptr };
    const bool is_manager{ false };
    const bool is_ghost{ false };
    pthread_t heartbeat_thread{ 0 };
};

} // namespace cat_ipc

#endif /* IPCB_HPP_ */