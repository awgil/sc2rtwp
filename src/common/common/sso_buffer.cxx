module;

#include <assert.h>

module common:sso_buffer;

import std;

// SSO buffer is a resizeable memory buffer with optional embedded "small-string optimization" buffer.
// It always deals with uninitialized memory (T is just a convenience, used only for determining element size), so it is up to users to actually construct and destruct objects in the buffer.
// One invariant that it keeps is the following: capacity is either == FixedSize (then data points to embedded storage) or > FixedSize (then data points to managed piece of memory and embedded storage is unused & inaccessible).
template<typename T, size_t FixedSize>
class SSOBuffer
{
public:
	using allocator_type = std::allocator<T>;

	// Construct without any dynamic allocations.
	SSOBuffer() = default;

	// Construct with specified capacity.
	SSOBuffer(size_t capacity)
	{
		if (capacity > FixedSize)
		{
			realloc(capacity);
		}
	}

	// Copy and move are disabled.
	SSOBuffer(const SSOBuffer&) = delete;
	SSOBuffer(SSOBuffer&&) = delete;
	SSOBuffer& operator=(const SSOBuffer&) = delete;
	SSOBuffer& operator=(SSOBuffer&&) = delete;

	~SSOBuffer() { resetExternal(); }

	// Resize: determine automatically which buffer to use. Call functor so that it can move data.
	template<typename TFunc>
	void realloc(size_t capacity, TFunc&& func)
	{
		bool newInEmbedded = capacity <= FixedSize;
		bool curInEmbedded = mCapacity <= FixedSize;
		if (newInEmbedded && curInEmbedded)
			return; // nothing to do...

		T* newData = newInEmbedded ? embeddedStorage() : allocator_type().allocate(capacity);
		func(data(), newData);
		setFields(capacity, newData);
	}

	// Try stealing data pointer from other SSO buffer; it's only possible if size is larger than both our and victim's capacity, otherwise we'd break invariant.
	template<size_t RhsFixedSize>
	bool steal(SSOBuffer<T, RhsFixedSize>&& victim)
	{
		size_t victimCapacity = victim.capacity();
		if (victimCapacity <= RhsFixedSize || victimCapacity <= FixedSize)
		{
			// (1) - buffer can't be stolen, since it's embedded into victim
			// (2) - buffer can't be stolen, since if we did that, we'd break our invariant
			return false;
		}

		setFields(victimCapacity, victim.mExternal);
		victim.setFields(RhsFixedSize, victim.embeddedStorage());
		return true;
	}

	/* Accessors. */
	size_t capacity() const { return mCapacity; }
	T* data() { return usesExternalStorage() ? mExternal : embeddedStorage(); }
	const T* data() const { return usesExternalStorage() ? mExternal : embeddedStorage(); }

private:
	bool usesExternalStorage() const { return mCapacity > FixedSize; }
	T* embeddedStorage() { return reinterpret_cast<T*>(&mEmbedded); }
	const T* embeddedStorage() const { return reinterpret_cast<const T*>(&mEmbedded); }

	void resetExternal()
	{
		if (usesExternalStorage())
			allocator_type().deallocate(mExternal, mCapacity);
	}

	void setFields(size_t capacity, T* data)
	{
		resetExternal();
		if (capacity <= FixedSize)
		{
			assert(data == embeddedStorage());
			mCapacity = FixedSize;
		}
		else
		{
			assert(data != embeddedStorage());
			mCapacity = capacity;
			mExternal = data;
		}
	}

private:
	size_t mCapacity = FixedSize;
	union
	{
		T* mExternal;
		alignas(T) char mEmbedded[sizeof(T) * FixedSize];
	};
};
