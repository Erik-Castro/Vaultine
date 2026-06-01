#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <type_traits>

namespace ssm::v1 {

void secure_erase(void* ptr, size_t len) noexcept;

template <typename T>
void secure_erase(T& obj) noexcept {
    static_assert(std::is_trivially_copyable_v<T>,
                  "secure_erase requires a trivially copyable type");
    secure_erase(&obj, sizeof(T));
}

// secure_alloc: allocate memory locked with mlock() to prevent swapping.
// Returns nullptr on failure (allocation or mlock).
void* secure_alloc(size_t size) noexcept;

// secure_free: unm lock and free memory allocated by secure_alloc.
void secure_free(void* ptr, size_t size) noexcept;

// secure_buffer: RAII wrapper over secure_alloc/secure_free.
template <typename T>
class secure_buffer {
    static_assert(std::is_trivially_copyable_v<T>);
public:
    secure_buffer() = default;

    explicit secure_buffer(size_t count)
        : data_(static_cast<T*>(secure_alloc(count * sizeof(T))))
        , size_(data_ ? count : 0)
    {
        if (data_)
            for (size_t i = 0; i < size_; ++i)
                ::new (data_ + i) T{};
    }

    secure_buffer(secure_buffer const&) = delete;
    auto operator=(secure_buffer const&) -> secure_buffer& = delete;

    secure_buffer(secure_buffer&& other) noexcept
        : data_(other.data_), size_(other.size_)
    {
        other.data_ = nullptr;
        other.size_ = 0;
    }

    auto operator=(secure_buffer&& other) noexcept -> secure_buffer& {
        if (this != &other) {
            release();
            data_ = other.data_;
            size_ = other.size_;
            other.data_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    ~secure_buffer() noexcept { release(); }

    T* data() noexcept { return data_; }
    const T* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    explicit operator bool() const noexcept { return data_ != nullptr; }

    T& operator[](size_t i) noexcept { return data_[i]; }
    const T& operator[](size_t i) const noexcept { return data_[i]; }

    T* begin() noexcept { return data_; }
    T* end() noexcept { return data_ + size_; }
    const T* begin() const noexcept { return data_; }
    const T* end() const noexcept { return data_ + size_; }

private:
    void release() noexcept {
        if (data_) {
            for (size_t i = 0; i < size_; ++i)
                data_[i].~T();
            secure_erase(data_, size_ * sizeof(T));
            secure_free(data_, size_ * sizeof(T));
            data_ = nullptr;
            size_ = 0;
        }
    }

    T* data_ = nullptr;
    size_t size_ = 0;
};

template <typename T>
class secure_vector {
    static_assert(std::is_trivially_copyable_v<T>);

public:
    using value_type = T;
    using size_type = size_t;
    using pointer = T*;
    using const_pointer = T const*;
    using iterator = pointer;
    using const_iterator = const_pointer;

    secure_vector() = default;

    explicit secure_vector(size_type count)
        : data_(static_cast<pointer>(::operator new[](count * sizeof(T)))), size_(count) {
        for (size_type i = 0; i < size_; ++i)
            ::new (data_ + i) T{};
    }

    secure_vector(secure_vector const&) = delete;
    auto operator=(secure_vector const&) -> secure_vector& = delete;

    secure_vector(secure_vector&& other) noexcept : data_(other.data_), size_(other.size_) {
        other.data_ = nullptr;
        other.size_ = 0;
    }

    auto operator=(secure_vector&& other) noexcept -> secure_vector& {
        if (this != &other) {
            clear();
            data_ = other.data_;
            size_ = other.size_;
            other.data_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    ~secure_vector() noexcept { clear(); }

    pointer data() noexcept { return data_; }
    const_pointer data() const noexcept { return data_; }
    size_type size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }

    T& operator[](size_type i) noexcept { return data_[i]; }
    T const& operator[](size_type i) const noexcept { return data_[i]; }

    iterator begin() noexcept { return data_; }
    iterator end() noexcept { return data_ + size_; }
    const_iterator begin() const noexcept { return data_; }
    const_iterator end() const noexcept { return data_ + size_; }

    void resize(size_type new_size) {
        if (new_size == size_)
            return;
        auto* new_data = static_cast<pointer>(::operator new[](new_size * sizeof(T)));
        auto copy_size = std::min(size_, new_size);
        for (size_type i = 0; i < copy_size; ++i)
            ::new (new_data + i) T(data_[i]);
        for (size_type i = copy_size; i < new_size; ++i)
            ::new (new_data + i) T{};
        clear();
        data_ = new_data;
        size_ = new_size;
    }

    void clear() noexcept {
        if (data_) {
            for (size_type i = 0; i < size_; ++i)
                data_[i].~T();
            secure_erase(data_, size_ * sizeof(T));
            ::operator delete[](data_);
            data_ = nullptr;
            size_ = 0;
        }
    }

private:
    pointer data_ = nullptr;
    size_type size_ = 0;
};

}  // namespace ssm::v1
