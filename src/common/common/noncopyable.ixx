export module common:noncopyable;

// Classes derived from 'Noncopyable' won't have auto-generated copy constructors. This doesn't suppress auto-generation of move constructors.
export class Noncopyable
{
protected:
	Noncopyable() = default;
	~Noncopyable() = default;

	Noncopyable(const Noncopyable&) = delete;
	Noncopyable& operator=(const Noncopyable&) = delete;

	Noncopyable(Noncopyable&&) = default;
	Noncopyable& operator=(Noncopyable&&) = default;
};

// Classes derived from 'nonmovable' won't have auto-generated copy or move constructors.
export class Nonmovable
{
protected:
	Nonmovable() = default;
	~Nonmovable() = default;

	Nonmovable(const Nonmovable&) = delete;
	Nonmovable& operator=(const Nonmovable&) = delete;

	Nonmovable(Nonmovable&&) = delete;
	Nonmovable& operator=(Nonmovable&&) = delete;
};
