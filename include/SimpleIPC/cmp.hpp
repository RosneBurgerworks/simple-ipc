/*
 * cmp.hpp
 *
 * Created on: Mar 18, 2017
 * Author: nullifiedcat
 */

#ifndef CMP_HPP_
#define CMP_HPP_

#include <stddef.h>
#include <stdint.h>

class CatMemoryPool {
public:
    inline CatMemoryPool(void *base, size_t size) : base(base), size(size) {}

    struct PoolBlock {
        bool free;
        size_t size;
        void *prev;
        void *next;
    };

    struct PoolInfo {
        unsigned long free;
        unsigned long alloc;
        unsigned int freeBlocks;
        unsigned int allocBlocks;
        unsigned int blockCount;
    };

    inline void init() {
        memset(base, 0, size);
        PoolBlock zerothBlock;
        zerothBlock.free = true;
        zerothBlock.next = (PoolBlock *) -1;
        zerothBlock.prev = (PoolBlock *) -1;
        zerothBlock.size = size;
        memcpy(base, &zerothBlock, sizeof(PoolBlock));
    }
    
    inline void *alloc(size_t size) {
        PoolBlock *block = findBlock(size);
        if (block == (PoolBlock *) -1) {
            return (void *) 0;
        }
        chipBlock(block, size);
        block->free = false;
        return (void *)((uintptr_t)(block) + sizeof(PoolBlock));
    }
    
    inline void free(void *object) {
        PoolBlock *block = (PoolBlock *)((uintptr_t)object - sizeof(PoolBlock));
        block->free = true;
        mendBlock(block);
    }

    inline void statistics(PoolInfo &info) {
        memset(&info, 0, sizeof(PoolInfo));
        PoolBlock *current = (PoolBlock *)base;
        while (current) {
            if (current->free) {
                info.freeBlocks++;
                info.free += current->size;
            }
            info.blockCount++;
            if (current->next == (void *) -1)
                break;
            current = realPointer<PoolBlock>(current->next);
        }
        info.alloc = size - info.free;
        info.allocBlocks = info.blockCount - info.freeBlocks;
    }

    template <typename T>
    inline T *realPointer(void *pointer) const {
        return reinterpret_cast<T *>((uintptr_t)base + (uintptr_t)pointer);
    }

    template <typename T>
    inline void *poolPointer(T *pointer) const {
        return (void *)((uintptr_t)pointer - (uintptr_t)base);
    }

    void *base;
    const size_t size;

protected:
    inline PoolBlock *findBlock(size_t size) {
        PoolBlock *current = (PoolBlock *)base;
        while (current) {
            if (current->free) {
                if (current->size >= size)
                    return current;
            }
            if (current->next == (void *) -1)
                break;
            current = realPointer<PoolBlock>(current->next);
        }
        return (PoolBlock *) -1;
    }

    inline void chipBlock(PoolBlock *block, size_t size) {
        if (block->size - sizeof(PoolBlock) > size) {
            unsigned oldSize = block->size;
            block->size = size;
            PoolBlock newBlock;
            newBlock.prev = poolPointer<void>(block);
            newBlock.next = block->next;
            newBlock.free = 1;
            newBlock.size = oldSize - (size + sizeof(PoolBlock));
            void *pNewBlock = (void *)((unsigned)poolPointer<void>(block) + sizeof(PoolBlock) + block->size);
            if (block->next != (void *) -1) {
                realPointer<PoolBlock>(block->next)->prev = pNewBlock;
            }
            block->next = pNewBlock;
            memcpy(realPointer<void>(pNewBlock), &newBlock, sizeof(PoolBlock));
        }
    }

    inline void mendBlock(PoolBlock *block) {
        if (block->prev != (void *) -1) {
            PoolBlock *curPrev = realPointer<PoolBlock>(block->prev);
            if (curPrev->free) {
                mendBlock(curPrev);
                return;
            }
        }
        if (block->next != (void *) -1) {
            PoolBlock *curNext = realPointer<PoolBlock>(block->next);
            while (curNext->free) {
                block->size += sizeof(PoolBlock) + curNext->size;
                deleteBlock(curNext);
                if (block->next != (void *) -1) {
                    curNext = realPointer<PoolBlock>(block->next);
                } else {
                    break;
                }
            }
        }
    }

    inline void deleteBlock(PoolBlock *block) {
        if (block->next != (void *) -1)
            realPointer<PoolBlock>(block->next)->prev = block->prev;
        if (block->prev != (void *) -1)
            realPointer<PoolBlock>(block->prev)->next = block->next;
    }
};

#endif /* CMP_HPP_ */
