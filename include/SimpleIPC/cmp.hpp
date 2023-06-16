/*
 * cmp.hpp
 *
 *  Created on: Mar 18, 2017
 *      Author: nullifiedcat
 */

#pragma once

#include <cstddef>
#include <cstdint>

class CatMemoryPool
{
public:
    inline CatMemoryPool(void *base, size_t size) : base(base), size(size)
    {
    }

    struct pool_block_s
    {
        bool free;
        size_t size;
        void *prev;
        void *next;
    };

    struct pool_info_s
    {
        unsigned long free;
        unsigned long alloc;
        unsigned freeblk;
        unsigned allocblk;
        unsigned blkcnt;
    };

    inline void init() const
    {
        memset(base, 0, size);
        pool_block_s zeroth_block{};
        zeroth_block.free = true;
        zeroth_block.next = (pool_block_s *) -1;
        zeroth_block.prev = (pool_block_s *) -1;
        zeroth_block.size = size;
        memcpy(base, &zeroth_block, sizeof(pool_block_s));
    }

    inline void *alloc(size_t size)
    {
        pool_block_s *block = FindBlock(size);
        if (block == (pool_block_s *) -1)
            return (void *) nullptr;

        ChipBlock(block, size);
        block->free = false;
        return (void *) ((uintptr_t)(block) + sizeof(pool_block_s));
    }

    inline void free(void *object)
    {
        auto *block = (pool_block_s *) ((uintptr_t) object - sizeof(pool_block_s));
        block->free         = true;
        MendBlock(block);
    }

    inline void statistics(pool_info_s &info) const
    {
        memset(&info, 0, sizeof(pool_info_s));
        auto *current = (pool_block_s *) base;
        while (current)
        {
            if (current->free)
            {
                info.freeblk++;
                info.free += current->size;
            }
            info.blkcnt++;
            if (current->next == (void *) -1)
                break;
            current = real_pointer<pool_block_s>(current->next);
        }
        info.alloc    = size - info.free;
        info.allocblk = info.blkcnt - info.freeblk;
    }

    template <typename T> inline T *real_pointer(void *pointer) const
    {
        return reinterpret_cast<T *>((uintptr_t) base + (uintptr_t) pointer);
    }

    template <typename T> inline void *pool_pointer(T *pointer) const
    {
        return (void *) ((uintptr_t) pointer - (uintptr_t) base);
    }

    void *base;
    const size_t size;

protected:
    inline pool_block_s *FindBlock(size_t size) const
    {
        auto *current = (pool_block_s *) base;
        while (current)
        {
            if (current->free && current->size >= size)
                return current;

            if (current->next == (void *) -1)
                break;
            current = real_pointer<pool_block_s>(current->next);
        }
        return (pool_block_s *) -1;
    }

    inline void ChipBlock(pool_block_s *block, size_t size) const
    {
        if (block->size - sizeof(pool_block_s) > size)
        {
            unsigned old_size = block->size;
            block->size       = size;
            pool_block_s new_block{};
            new_block.prev    = pool_pointer<void>(block);
            new_block.next    = block->next;
            new_block.free    = true;
            new_block.size    = old_size - (size + sizeof(pool_block_s));
            void *p_new_block = (void *) ((unsigned) pool_pointer<void>(block) + sizeof(pool_block_s) + block->size);
            if (block->next != (void *) -1)
                real_pointer<pool_block_s>(block->next)->prev = p_new_block;
            block->next = p_new_block;
            memcpy(real_pointer<void>(p_new_block), &new_block, sizeof(pool_block_s));
        }
    }

    inline void MendBlock(pool_block_s *block)
    {
        if (block->prev != (void *) -1)
        {
            auto *cur_prev = real_pointer<pool_block_s>(block->prev);
            if (cur_prev->free)
            {
                MendBlock(cur_prev);
                return;
            }
        }
        if (block->next != (void *) -1)
        {
            auto *cur_next = real_pointer<pool_block_s>(block->next);
            while (cur_next->free)
            {
                block->size += sizeof(pool_block_s) + cur_next->size;
                DeleteBlock(cur_next);
                if (block->next != (void *) -1)
                    cur_next = real_pointer<pool_block_s>(block->next);
                else
                    break;
            }
        }
    }

    inline void DeleteBlock(pool_block_s *block) const
    {
        if (block->next != (void *) -1)
            real_pointer<pool_block_s>(block->next)->prev = block->prev;
        if (block->prev != (void *) -1)
            real_pointer<pool_block_s>(block->prev)->next = block->next;
    }
};
