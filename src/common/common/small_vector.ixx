module;

#include <assert.h>

export module common:small_vector;

import std;
import :sso_buffer;

// Small vector is a drop-in replacement for std::vector that contains embedded buffer of fixed size.
// This allows avoiding any dynamic allocations until number of elements becomes greater than fixed capacity.
// Note that size could be zero - in such case it is equivalent to usual vector.
// Exception safety: basic if T's destructor and move constructor don't throw, unsafe otherwise.
// TODO: insert(InputIt) + concept checks
export  template<typename T, size_t FixedSize> class SmallVector
{
public:
	// Standard typedefs.
	using value_type = T;
	using allocator_type = typename SSOBuffer<T, FixedSize>::allocator_type;
	using size_type = size_t;
	using difference_type = ptrdiff_t;
	using reference = T&;
	using const_reference = const T&;
	using pointer = typename std::allocator_traits<allocator_type>::pointer;
	using const_pointer = typename std::allocator_traits<allocator_type>::const_pointer;
	using iterator = pointer;
	using const_iterator = const_pointer;
	using reverse_iterator = std::reverse_iterator<iterator>;
	using const_reverse_iterator = std::reverse_iterator<const_iterator>;

	// Default constructor creates an empty vector. Initial capacity is equal to embedded buffer size.
	SmallVector() noexcept {}

	// Create/assign N copies of specified value.
	explicit SmallVector(size_type count, const T& value = T()) { insert(begin(), count, value); }

	void assign(size_type count, const T& value)
	{
		clear();
		insert(begin(), count, value);
	}

	// Create a vector with contents from specified range.
	template<typename InputIt>
	SmallVector(InputIt first, InputIt last)
	{
		insert(begin(), first, last);
	}

	template<typename InputIt>
	void assign(InputIt first, InputIt last)
	{
		clear();
		insert(begin(), first, last);
	}

	template<std::ranges::range R>
	SmallVector(R&& range)
	{
		insert(begin(), range.begin(), range.end());
	}

	// Create/assign from initializer list.
	SmallVector(std::initializer_list<T> init) { insert(begin(), init.begin(), init.end()); }

	SmallVector& operator=(std::initializer_list<T> init)
	{
		assign(init.begin(), init.end());
		return *this;
	}

	void assign(std::initializer_list<T> init)
	{
		clear();
		insert(begin(), init.begin(), init.end());
	}

	// Copy & move.
	SmallVector(const SmallVector& rhs) { insert(begin(), rhs.begin(), rhs.end()); }

	SmallVector& operator=(const SmallVector& rhs)
	{
		assign(rhs.begin(), rhs.end());
		return *this;
	}

	template<size_t RhsFixedSize>
	SmallVector(const SmallVector<T, RhsFixedSize>& rhs)
	{
		insert(begin(), rhs.begin(), rhs.end());
	}

	template<size_t RhsFixedSize>
	SmallVector& operator=(const SmallVector<T, RhsFixedSize>& rhs)
	{
		assign(rhs.begin(), rhs.end());
		return *this;
	}

	SmallVector(SmallVector&& rhs) { moveAssign(std::move(rhs)); }

	SmallVector& operator=(SmallVector&& rhs)
	{
		clear();
		moveAssign(std::move(rhs));
		return *this;
	}

	template<size_t RhsFixedSize>
	SmallVector(SmallVector<T, RhsFixedSize>&& rhs)
	{
		moveAssign(std::move(rhs));
	}

	template<size_t RhsFixedSize>
	SmallVector& operator=(SmallVector<T, RhsFixedSize>&& rhs)
	{
		clear();
		moveAssign(std::move(rhs));
		return *this;
	}

	~SmallVector() { clear(); }

	// Element access.
	reference at(size_type pos)
	{
		if (pos < mSize)
			return mBuffer.data()[pos];
		else
			throw std::out_of_range("out of range");
	}

	const_reference at(size_type pos) const
	{
		if (pos < mSize)
			return mBuffer.data()[pos];
		else
			throw std::out_of_range("out of range");
	}

	reference operator[](size_type pos) { return mBuffer.data()[pos]; }
	const_reference operator[](size_type pos) const { return mBuffer.data()[pos]; }
	reference front() { return mBuffer.data()[0]; }
	const_reference front() const { return mBuffer.data()[0]; }
	reference back() { return mBuffer.data()[mSize - 1]; }
	const_reference back() const { return mBuffer.data()[mSize - 1]; }
	T* data() noexcept { return mBuffer.data(); }
	const T* data() const noexcept { return mBuffer.data(); }

	// Iterators.
	iterator begin() noexcept { return mBuffer.data(); }
	const_iterator begin() const noexcept { return mBuffer.data(); }
	const_iterator cbegin() const noexcept { return mBuffer.data(); }
	iterator end() noexcept { return mBuffer.data() + mSize; }
	const_iterator end() const noexcept { return mBuffer.data() + mSize; }
	const_iterator cend() const noexcept { return mBuffer.data() + mSize; }
	reverse_iterator rbegin() noexcept { return reverse_iterator(end()); }
	const_reverse_iterator rbegin() const noexcept { return const_reverse_iterator(end()); }
	const_reverse_iterator crbegin() const noexcept { return const_reverse_iterator(end()); }
	reverse_iterator rend() noexcept { return reverse_iterator(begin()); }
	const_reverse_iterator rend() const noexcept { return const_reverse_iterator(begin()); }
	const_reverse_iterator crend() const noexcept { return const_reverse_iterator(begin()); }

	// Vector size accessors.
	bool empty() const noexcept { return mSize == 0; }
	size_type size() const noexcept { return mSize; }
	size_type capacity() const noexcept { return mBuffer.capacity(); }

	// Theoretical limit on vector size.
	constexpr size_type max_size() const noexcept { return std::numeric_limits<size_type>::max() / sizeof(T); }

	// Increase the capacity to be greater or equal to desired value.
	void reserve(size_type desired)
	{
		if (desired > capacity())
		{
			mBuffer.realloc(desired, [this](T* from, T* to) { moveElements(from, to, mSize); });
		}
	}

	// Reserve using growth heuristic.
	void reserveImprecise(size_type desired)
	{
		if (desired > capacity())
		{
			mBuffer.realloc(growHeuristic(desired), [this](T* from, T* to) { moveElements(from, to, mSize); });
		}
	}

	// Remove all elements. Capacity is not changed.
	void clear() noexcept
	{
		for (T *p = begin(), *e = end(); p < e; ++p)
			p->~T();
		mSize = 0;
	}

	// Insert value at (before) specified position.
	iterator insert(const_iterator pos, const T& value)
	{
		T* gap = createGap(1, pos);
		try
		{
			new(gap) T(value);
		}
		catch (...)
		{
			removeGap(1, gap);
			throw;
		}
		return gap;
	}

	iterator insert(const_iterator pos, T&& value)
	{
		T* gap = createGap(1, pos);
		// note that we don't provide exception safety if move throws, so no need for try/catch here
		new(gap) T(std::move(value));
		return gap;
	}

	// Insert N copies of specified value at specified position.
	iterator insert(const_iterator pos, size_type count, const T& value)
	{
		T* gap = createGap(count, pos);
		T* lastConstructed = gap;
		try
		{
			for (T* e = gap + count; lastConstructed < e; ++lastConstructed)
				new(lastConstructed) T(value);
		}
		catch (...)
		{
			for (T* p = gap; p < lastConstructed; ++p)
				p->~T();
			removeGap(count, gap);
			throw;
		}
		return gap;
	}

	// Insert elements from range at specified position. TODO: we can relax to InputIterator, at the cost of efficiency.
	template<typename TFwdIt>
	iterator insert(const_iterator pos, TFwdIt first, TFwdIt last)
	{
		size_type count = last - first;
		T* gap = createGap(count, pos);
		T* lastConstructed = gap;
		try
		{
			for (; first != last; ++first, ++lastConstructed)
				new(lastConstructed) T(*first);
		}
		catch (...)
		{
			for (T* p = gap; p < lastConstructed; ++p)
				p->~T();
			removeGap(count, gap);
			throw;
		}
		return gap;
	}

	// Insert elements from initializer list at specified position.
	iterator insert(const_iterator pos, std::initializer_list<T> init) { return insert(pos, init.begin(), init.end()); }

	// Construct element in-place at specified position.
	template<typename... TArgs>
	iterator emplace(const_iterator pos, TArgs&&... args)
	{
		T* gap = createGap(1, pos);
		try
		{
			new(gap) T(std::forward<TArgs>(args)...);
		}
		catch (...)
		{
			removeGap(1, gap);
			throw;
		}
		return gap;
	}

	// Construct multiple elements in-place at specified position.
	template<typename... TArgs>
	iterator emplaceMany(const_iterator pos, size_type count, TArgs&&... args)
	{
		T* gap = createGap(count, pos);
		T* lastConstructed = gap;
		try
		{
			for (T* e = gap + count; lastConstructed < e; ++lastConstructed)
				new(lastConstructed) T(std::forward<TArgs>(args)...);
		}
		catch (...)
		{
			for (T* p = gap; p < lastConstructed; ++p)
				p->~T();
			removeGap(count, gap);
			throw;
		}
		return gap;
	}

	// Erase element at specified position.
	iterator erase(const_iterator pos)
	{
		T* p = data() + (pos - data());
		p->~T();
		removeGap(1, p);
		return p;
	}

	// Erase a range of elements.
	iterator erase(const_iterator first, const_iterator last)
	{
		T* begin = data() + (first - data());
		size_type count = last - first;
		for (T* p = begin; p < last; ++p)
			p->~T();
		removeGap(count, begin);
		return begin;
	}

	// Append value to the end.
	void push_back(const T& value) { insert(end(), value); }
	void push_back(T&& value) { insert(end(), std::move(value)); }

	// Construct element in-place at the end.
	template<typename... TArgs>
	reference emplace_back(TArgs&&... args)
	{
		return *emplace(end(), std::forward<TArgs>(args)...);
	}

	// Remove last element.
	void pop_back()
	{
		back().~T();
		--mSize;
	}

	// Resize: either remove last elements or fill with copies of default (or specified) value.
	void resize(size_type count)
	{
		if (size < mSize)
		{
			erase(begin() + size, end());
		}
		else if (size > mSize)
		{
			emplaceMany(end(), size - mSize);
		}
	}

	void resize(size_type count, const T& value)
	{
		if (size < mSize)
		{
			erase(begin() + size, end());
		}
		else if (size > mSize)
		{
			insert(end(), size - mSize, value);
		}
	}

private:
	// Heuristic to calculate new capacity to grow to that should be >= desired size.
	size_type growHeuristic(size_type desired)
	{
		// try growing by a factor of 1.5
		size_type growth = capacity() / 2;
		if (capacity() > max_size() - growth)
			return desired; // default growth would overflow
		else
			return std::max(capacity() + growth, desired);
	}

	// Move a bunch of elements between storages: uses move-constructor and destroys source. Destination is assumed to be uninitialized, source is left uninitialized.
	static void moveElements(T* from, T* to, size_type count)
	{
		for (T *end = from + count; from < end; ++from, ++to)
		{
			new(to) T(std::move(*from));
			from->~T();
		}
	}

	// A variation of move_elements working in reversed order.
	static void moveElementsReverse(T* from, T* to, size_type count)
	{
		to += count;
		for (T* p = from + count; p-- > from;)
		{
			new(--to) T(std::move(*p));
			p->~T();
		}
	}

	// Create uninitialized gap of specified size at specified position. Size is increased, so make sure to initialize elements in the gap after calling.
	T* createGap(size_type count, const_iterator pos)
	{
		size_type offset = pos - data();
		size_type newSize = mSize + count;
		if (newSize > capacity())
		{
			// reallocate & create gap in a single pass
			mBuffer.realloc(growHeuristic(newSize), [this, offset, count](T* from, T* to) {
				moveElements(from, to, offset);
				moveElements(from + offset, to + offset + count, mSize - offset);
			});
		}
		else
		{
			// enough space, just move elements after pos
			moveElementsReverse(data() + offset, data() + offset + count, mSize - offset);
		}
		mSize = newSize;
		return data() + offset;
	}

	// Remove uninitialized gap of specified size at specified position. Size is decreased.
	void removeGap(size_type count, const_iterator pos)
	{
		size_type offset = pos - data();
		moveElements(data() + offset + count, data() + offset, mSize - offset - count);
		mSize -= count;
	}

	// Move assignment implementation.
	template<size_t RhsFixedSize>
	void moveAssign(SmallVector<T, RhsFixedSize>&& rhs)
	{
		assert(mSize == 0);
		if (!mBuffer.steal(std::move(rhs.mBuffer)))
		{
			// steal failed, do the move hard way...
			mBuffer.realloc(rhs.mSize, [](T* from, T* to) {});
			moveElements(rhs.data(), mBuffer.data(), rhs.mSize);
			// don't bother reallocating rhs buffer...
		}
		mSize = rhs.mSize;
		rhs.mSize = 0;
	}

private:
	size_type mSize = 0;
	SSOBuffer<T, FixedSize> mBuffer;
};
