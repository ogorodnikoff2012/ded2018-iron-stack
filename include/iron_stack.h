#pragma once

#include <functional>
#include <cstdlib>
#include <memory>
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <iostream>
#include <cstring>
#include <vector>
#include <algorithm>

#include "murmur3.h"

#define PM_READ 1
#define PM_WRITE 2
#define PM_EXECUTE 4

#ifdef __linux__
static bool FindPageMode(const void* pointer, int* rights) {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) {
        return false;
    }
    while (!feof(maps)) {
        unsigned long long low, high;
        char perms[6];
        fscanf(maps, "%Lx-%Lx %s%*[^\n]\n", &low, &high, perms);
        unsigned long long raw_pointer = (unsigned long long)(pointer);
        if (low <= raw_pointer && raw_pointer <= high) {
            *rights = 0;
            if (perms[0] == 'r') {
                *rights |= PM_READ;
            }
            if (perms[1] == 'w') {
                *rights |= PM_WRITE;
            }
            if (perms[2] == 'x') {
                *rights |= PM_EXECUTE;
            }
            fclose(maps);
            return true;
        }
    }
    fclose(maps);
    return false;
}
#endif

static bool CheckPointerRights(const void* pointer, int rights) {
#if PARANOIA_LEVEL >= 2
#ifdef __linux__
    int page_mode = 0;
    if (FindPageMode(pointer, &page_mode)) {
        return (page_mode & rights) == rights;
    }
#endif
#endif
    return pointer != nullptr;
}

static bool IsAValidPointer(const void* pointer) {
    return CheckPointerRights(pointer, PM_READ);
}

static bool IsAValidPointer(void* pointer) {
    return CheckPointerRights(pointer, PM_READ | PM_WRITE);
}

static std::FILE* GetDumpFile() {
#if PARANOIA_LEVEL >= 1
    if (fileno(stderr) == -1) {
        freopen("iron_stack.log", "w", stderr);
    }
#endif
    return stderr;
}

#define EVERYTHING_IS_BAD(message) \
    external_verificator_.Damage(); \
    pointer_manager_.Damage(); \
    FILE* f = GetDumpFile(); \
    std::fprintf(f, "Error in %s (%s:%d), validator message: %s\n", __PRETTY_FUNCTION__, __FILE__, __LINE__, message); \
    Dump(f); \
    std::exit(1); \

#define ASSERT_OK {\
    const char* validator_reason = "OK"; \
    bool validator_verdict = Validate(&validator_reason); \
    if (!validator_verdict) { \
        EVERYTHING_IS_BAD(validator_reason); \
    } \
}

class ExternalVerificator {
    public:
        ExternalVerificator() {
#if PARANOIA_LEVEL >= 3
            int to_pipe[2], from_pipe[2];
            if (pipe(to_pipe) == -1) {
                perror("pipe");
                std::exit(1);
            }
            if (pipe(from_pipe) == -1) {
                perror("pipe");
                std::exit(1);
            }
            in = fdopen(from_pipe[0], "r");
            out = fdopen(to_pipe[1], "w");

            external_verificator_pid = fork();
            if (external_verificator_pid == -1) {
                perror("fork");
                std::exit(1);
            }

            if (external_verificator_pid == 0) {
                dup2(to_pipe[0], STDIN_FILENO);
                dup2(from_pipe[1], STDOUT_FILENO);
                close(to_pipe[1]);
                close(from_pipe[0]);
                if (execl("./verificator", "./verificator", NULL) == -1) {
                    std::string str;
                    std::cout << "error" << std::endl;
                    std::cin >> str;
                    std::exit(1);
                }
            }
            close(to_pipe[0]);
            close(from_pipe[1]);
            char buffer[10];
            std::fscanf(in, "%5s", buffer);
            std::fprintf(out, "ready\n");
            std::fflush(out);

            if (std::strcmp(buffer, "ready") != 0) {
                fprintf(stderr, "Verificator `./verificator` is broken!\n");
                std::exit(1);
            }
            damaged = false;
#endif
        }

        bool CheckBinary(const char* name, int expected_size, const uint8_t* expected_value) const {
#if PARANOIA_LEVEL >= 3
            if (!CheckName(name)) {
                return false;
            }
            std::fprintf(out, "get size %s\n", name);
            std::fflush(out);
            int64_t size;
            std::fscanf(in, "%ld", &size);
            if (size != expected_size) {
                return false;
            }

            for (int i = 0; i < size; ++i) {
                std::fprintf(out, "get at %d %s\n", i, name);
                std::fflush(out);
                uint8_t element;
                std::fscanf(in, "%hhu", &element);
                if (element != expected_value[i]) {
                    return false;
                }
            }
#endif
            return true;
        }

        void SetBinary(const char* name, int size, const uint8_t* value) const {
#if PARANOIA_LEVEL >= 3
            if (CheckName(name)) {
                std::fprintf(out, "set size %s %d\n", name, size);
                for (int i = 0; i < size; ++i) {
                    std::fprintf(out, "set at %d %s %hhu\n", i, name, value[i]);
                }
            }
#endif
        }

        template <class T>
        bool CheckObject(const char* name, const T& object) const {
            return CheckBinary(name, sizeof(T), (uint8_t*)(void*)(&object));
        }

        template <class T>
        void SetObject(const char* name, const T& object) const {
            SetBinary(name, sizeof(T), (uint8_t*)(void*)(&object));
        }

        void Dup(const char* name) const {
#if PARANOIA_LEVEL >= 3
            if (CheckName(name)) {
                std::fprintf(out, "dup %s\n", name);
            }
#endif
        }

        void Pop(const char* name) const {
#if PARANOIA_LEVEL >= 3
            if (CheckName(name)) {
                std::fprintf(out, "pop %s\n", name);
            }
#endif
        }

        ~ExternalVerificator() {
#if PARANOIA_LEVEL >= 3
            if (damaged) {
                kill(0, SIGKILL);
                while (wait(NULL) != -1) {}
            } else {
                std::fprintf(out, "exit\n");
                std::fflush(out);
                std::fclose(in);
                std::fclose(out);
                kill(external_verificator_pid, SIGTERM);
                while (waitpid(external_verificator_pid, NULL, 0) != -1) {}
            }
#endif
        }

        void Damage() const {
            damaged = true;
        }

        const uint8_t* InternalData() const {
            return (const uint8_t*)(void*)(in);
        }

        uint32_t InternalSize() const {
            return sizeof(*this) - sizeof(damaged);
        }

    private:
        static bool CheckName(const char* name) {
            for (; *name != '\0'; ++name) {
                if (*name <= ' ' || *name > '~') {
                    return false;
                }
            }
            return true;
        }
        mutable bool damaged;
        FILE* in;
        FILE* out;
        pid_t external_verificator_pid;
};

class PointerManager {
    public:
        void Add(const void* pointer) {
            pointers_.push_back(pointer);
            Update();
        }

        void Delete(const void* pointer) {
            auto iter = std::find(pointers_.begin(), pointers_.end(), pointer);
            if (iter != pointers_.end()) {
                std::swap(*iter, pointers_.back());
                pointers_.pop_back();
                Update();
            }
        }

        bool Contains(const void* pointer) {
            return std::find(pointers_.begin(), pointers_.end(), pointer) != pointers_.end();
        }

        bool Valid() const {
            return external_verificator_.CheckBinary("data", pointers_.size() * sizeof(const void*), (const uint8_t *)(const void*)pointers_.data());
        }

        void Damage() {
            external_verificator_.Damage();
        }
    private:
        void Update() {
            external_verificator_.SetBinary("data", pointers_.size() * sizeof(const void*), (const uint8_t *)(const void*)pointers_.data());
        }
        std::vector<const void*> pointers_;
        ExternalVerificator external_verificator_;
};

struct StackBase {
    static PointerManager pointer_manager_;
};

template <class T>
class IronStack : public StackBase {
public:
    static constexpr int kCanarySize = 16;
//    static constexpr int kPoisonValue = 0xFEE1DEAD;
    static constexpr int kCanaryRandomSeed = 0x8BADF00D;
    static constexpr int32_t kHashSumSeed = 0xABADBABE;
    static constexpr int kMinimalStackCapacity = 16;
    using Canary = std::array<int, kCanarySize>;
    Canary CanaryValue() const {
        Canary canary;
        Murmur3 generator(kHashSumSeed);
        generator << this;
        uint32_t this_hash = generator.GetHashSum();
        /* Algorithm "xor" from p. 4 of Marsaglia, "Xorshift RNGs" */
        uint32_t random_state = kCanaryRandomSeed ^ this_hash;
        for (int i = 0; i < kCanarySize; ++i) {
            canary[i] = random_state;
            random_state ^= (random_state << 13);
            random_state ^= (random_state >> 17);
            random_state ^= (random_state << 5);
        }
        return canary;
    }

    void AssertThisIsValid() {
        AssertIsValid(this);
    }

    void AssertThisIsValid() const {
        AssertIsValid(this);
    }

    IronStack()
        : canary_header_((AssertThisIsValid(), AssertPointerIsFree(), CanaryValue())),
        size_(0), capacity_(0), buffer_(nullptr), hash_sum_(0),
        canary_footer_(CanaryValue()) {
            pointer_manager_.Add(this);
            Resize(kMinimalStackCapacity);
            RecalcHashSum();
    }

    IronStack(const IronStack& other) = delete;
    IronStack(IronStack&& other) = delete;
    IronStack& operator=(const IronStack& other) = delete;
    IronStack& operator=(IronStack&& other) = delete;
    ~IronStack() {
        ASSERT_OK
            for (int i = 0; i < size_; ++i) {
                buffer_[i].~T();
            }
            std::free(GetFullBuffer());
            pointer_manager_.Delete(this);
    }

    template <class U>
    void Push(U&& value) {
        ASSERT_OK
        if (size_ >= capacity_) {
            Resize(2 * capacity_);
        }
        new (buffer_ + size_) T(std::forward<U>(value));
        external_verificator_.Dup("stack_top");
        external_verificator_.SetObject("stack_top", buffer_[size_]);
        ++size_;
        external_verificator_.SetObject("size", size_);
        RecalcHashSum();
        ASSERT_OK
    }

    const T& Top() const {
        ASSERT_OK
        if (size_ == 0) {
            EVERYTHING_IS_BAD("STACK_IS_EMPTY");
        }
        return buffer_[size_ - 1];
    }

    bool Pop() {
        ASSERT_OK
        if (size_ == 0) {
            return false;
        }
        --size_;
        buffer_[size_].~T();
        if (capacity_ > kMinimalStackCapacity && 4 * size_ <= capacity_) {
            Resize(capacity_ / 2);
        }
        external_verificator_.Pop("stack_top");
        external_verificator_.SetObject("size", size_);
        RecalcHashSum();
        ASSERT_OK
        return true;
    }
    bool IsEmpty() const {
        ASSERT_OK
        return size_ == 0;
    }

    int GetSize() const {
        ASSERT_OK
        return size_;
    }

    bool Validate(const char** reason = nullptr) const {
        const char* empty_string = "";
        const char** trusted_reason = &empty_string;
        if (IsAValidPointer(reason)) {
            trusted_reason = reason;
        }
#if PARANOIA_LEVEL >= 1
        if (!IsAValidPointer(this)) {
            *trusted_reason = "BAD_THIS_PTR";
            return false;
        }
#endif
        if (HashSum() != hash_sum_) {
            *trusted_reason = "BAD_HASH_SUM";
            return false;
        }

        if (BufferHashSum() != buffer_hash_sum_) {
            *trusted_reason = "BAD_BUFFER_HASH_SUM";
            return false;
        }
        if (size_ < 0 || size_ > capacity_) {
            *trusted_reason = "BAD_SIZE";
            return false;
        }
        if (!external_verificator_.CheckObject("size", size_)) {
            *trusted_reason = "BAD_EXTERNAL_SIZE";
            return false;
        }
        if (!external_verificator_.CheckObject("capacity", capacity_)) {
            *trusted_reason = "BAD_EXTERNAL_CAPACITY";
            return false;
        }
        if (size_ > 0 && !external_verificator_.CheckObject("stack_top", buffer_[size_ - 1])) {
            *trusted_reason = "BAD_EXTERNAL_STACK_TOP";
            return false;
        }
        *trusted_reason = "OK";
        return true;
    }
    void Dump(std::FILE* file) const {
#if PARANOIA_LEVEL >= 1
        if (fileno(file) == -1) {
            return;
        }
#endif
#define ASSERT_CANARY(canary) if ((canary) != CanaryValue()) { fprintf(file, " DAMAGED_CANARY"); }

        const char* validator_reason = "OK";
        bool validator_verdict = Validate(&validator_reason);
        fprintf(file, "IronStack [%p] (Validator: %c %s) {", this, validator_verdict ? '+' : '-', validator_reason);
        if (IsAValidPointer(this)) {
            fprintf(file, "\n\texpected canary: ");
            DumpArray(file, CanaryValue().data(), sizeof(int), kCanarySize, 1);
            fprintf(file, ",\n\tcanary_header_: ");
            DumpArray(file, canary_header_.data(), sizeof(int), kCanarySize, 1);
            ASSERT_CANARY(canary_header_);

            fprintf(file, ",\n\tsize_: %d", size_);
            fprintf(file, ",\n\tcapacity_: %d", capacity_);
            fprintf(file, ",\n\tbuffer_: (%p) ", buffer_);

            Canary* buffer_header = (Canary*)(void*)GetFullBuffer();
            Canary* buffer_footer = (Canary*)(void*)(GetFullBuffer() + sizeof(Canary) + sizeof(T) * capacity_);
            fprintf(file, "\n\t\tbuffer_header: ");
            DumpArray(file, buffer_header->data(), sizeof(int), kCanarySize, 2);
            ASSERT_CANARY(*buffer_header);

            fprintf(file, ",\n\t\tbuffer elements: ");
            DumpArray(file, buffer_, sizeof(T), capacity_, 2);


            fprintf(file, ",\n\t\tbuffer_footer: ");
            DumpArray(file, buffer_footer->data(), sizeof(int), kCanarySize, 2);
            ASSERT_CANARY(*buffer_footer);

            fprintf(file, ",\n\texternal_verificator: ");
            DumpArray(file, external_verificator_.InternalData(), 1, external_verificator_.InternalSize(), 1);

            fprintf(file, ",\n\thash: 0x%X", hash_sum_);
            fprintf(file, ",\n\tbuffer_hash: 0x%X", buffer_hash_sum_);

            fprintf(file, ",\n\tcanary_footer_: ");
            DumpArray(file, canary_footer_.data(), sizeof(int), kCanarySize, 1);
            ASSERT_CANARY(canary_footer_);
        }
        fprintf(file, "\n}\n");
    }
private:
    void Resize(int new_capacity) {
        int new_full_size = GetFullBufferSize(new_capacity);
        uint8_t* new_full_buffer = (uint8_t *)std::malloc(new_full_size);

        Canary* header = (Canary*)(void*)(new_full_buffer);
        T* new_buffer = (T*)(void*)(new_full_buffer + sizeof(Canary));
        Canary* footer = (Canary*)(void*)(new_full_buffer + sizeof(Canary) + sizeof(T) * new_capacity);

        if (buffer_ != nullptr) {
            for (int i = 0; i < size_ && i < new_capacity; ++i) {
                new (new_buffer + i) T(std::move(buffer_[i]));
                buffer_[i].~T();
            }
            std::free(GetFullBuffer());
        }

        *header = CanaryValue();
        *footer = CanaryValue();

        buffer_ = new_buffer;
        capacity_ = new_capacity;

        external_verificator_.SetObject("size", size_);
        external_verificator_.SetObject("capacity", capacity_);
    }

    void EverythingIsBad(const char* msg) const {
        std::FILE* dump = GetDumpFile();
        if (dump != nullptr) {
            std::fprintf(dump, "IronStack construction ERROR: %s\n", msg);
        }
        std::exit(1);
    }

    template <class This>
    void AssertIsValid(This pointer) const {
        if (!IsAValidPointer(pointer)) {
            EverythingIsBad("Pointer is not valid");
        }
    }

    void AssertPointerIsFree() const {
        if (pointer_manager_.Contains(this)) {
            EverythingIsBad("This pointer is already in use");
        }
    }

    static void NewLine(FILE* file, int indent) {
        fputc('\n', file);
        for (int j = 0; j < indent; ++j) {
            fputc('\t', file);
        }
    }

    static void DumpArray(FILE* file, const void* array, int size, int nmemb, int indent_size) {
        int items_per_line = 80 / (size + 4);
        if (items_per_line == 0) {
            ++items_per_line;
        }
        fputc('{', file);

        int index = items_per_line;
        for (int i = 0; i < nmemb; ++i, ++index) {
            if (index >= items_per_line) {
                index = 0;
                NewLine(file, indent_size + 1);
            }
            fputs("0x", file);
            for (int x = size - 1; x >= 0; --x) {
                fprintf(file, "%02hhX", *((const char *)(array) + i * size + x));
            }
            fputs(", ", file);
        }
        NewLine(file, indent_size);
        fputc('}', file);
    }

    uint32_t HashSum() const {
        Murmur3 generator(kHashSumSeed);
        generator << CanaryValue() << canary_header_ << size_ << capacity_ << buffer_ << external_verificator_.InternalData() << canary_footer_;
        return generator.GetHashSum();
    }

    uint32_t BufferHashSum() const {
        if (buffer_ == nullptr) {
            return kHashSumSeed;
        }
        Murmur3 generator(kHashSumSeed);
        generator << CanaryValue();
        generator.Append(GetFullBuffer(), GetFullBufferSize(capacity_));
        return generator.GetHashSum();

    }

    uint8_t* GetFullBuffer() const {
        return (uint8_t *)(void *)(buffer_) - sizeof(canary_header_);
    }

    uint32_t GetFullBufferSize(int capacity) const {
        return sizeof(canary_header_) + sizeof(canary_footer_) + capacity * sizeof(T);
    }

    void RecalcHashSum() {
        hash_sum_ = HashSum();
        buffer_hash_sum_ = BufferHashSum();
    }

    Canary canary_header_;
    int size_;
    int capacity_;
    T* buffer_;
    ExternalVerificator external_verificator_;
    uint32_t hash_sum_;
    uint32_t buffer_hash_sum_;
    Canary canary_footer_;
};

PointerManager StackBase::pointer_manager_;
