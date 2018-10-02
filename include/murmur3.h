#pragma once

#include <cstdint>

class Murmur3 {
public:
    explicit Murmur3(uint32_t seed) : hash_(seed), length_(0), remaining_size_(0) {}

    template <class T>
    Murmur3& operator<<(const T& data) {
        uint8_t* array = (uint8_t*)(void*)(&data);
        Append(array, sizeof(T));
        return *this;
    }

    void Append(uint8_t* data, int size) {
        for (int i = 0; i < size; ++i) {
            AppendByte(data[i]);
        }
    }

    uint32_t GetHashSum() const {
        uint32_t result = hash_;
        if (remaining_size_ > 0) {
            int data = FromLittleEndian();
            data *= kConst1;
            data = ROL(data, kRotate1);
            data *= kConst2;
            result ^= data;
        }

        result ^= length_;
        result ^= (result >> 16);
        result *= 0x85ebca6b;
        result ^= (result >> 13);
        result *= 0xc2b2ae35;
        result ^= (result >> 16);
        return result;
    }

private:
    void AppendByte(uint8_t byte) {
        remaining_bytes_[remaining_size_++] = byte;
        ++length_;
        if (remaining_size_ == 4) {
            uint32_t k = FromLittleEndian();
            k *= kConst1;
            k = ROL(k, kRotate1);
            k *= kConst2;

            hash_ ^= k;
            hash_ = ROL(hash_, kRotate2);
            hash_ *= kM;
            hash_ += kN;
            remaining_size_ = 0;
        }
    }

    uint32_t FromLittleEndian() const {
        uint32_t result = 0;
        for (int i = remaining_size_ - 1; i >= 0; --i) {
            result <<= 8;
            result |= remaining_bytes_[i];
        }
        return result;
    }

    uint32_t ROL(uint32_t value, int shift) const {
        return (value << shift) | (value >> (32 - shift));
    }

    static constexpr uint32_t kConst1 = 0xcc9e2d51;
    static constexpr uint32_t kConst2 = 0x1b873593;
    static constexpr uint32_t kRotate1 = 15;
    static constexpr uint32_t kRotate2 = 13;
    static constexpr uint32_t kM = 5;
    static constexpr uint32_t kN = 0xe6546b64;
    uint32_t hash_;
    uint32_t length_;
    uint8_t remaining_bytes_[4];
    uint32_t remaining_size_;
};
