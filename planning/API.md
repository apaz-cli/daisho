
# Table of Contents

Collections:
    trait Iterable<T>
    trait RandomIterable<T>

    trait Iterator<T>
    trait RandomIterator<T>

    trait Stream<T>

    class Array<T, Size_t size>
    class NDArray<T, Size_t dims...>
    trait List<T> impl RandomIterable<T>
    trait Map<K impl Hashable, V>
    trait Set<T>

    trait Hashable

Concurrency:
    class Thread
    class Mutex
    class RWLock
    class Atomic<T>
    class RWAtomic<T>

OS Stuff:
    trait Allocator
    class File
    trait Slice
    bare malloc(), realloc(), calloc(), free()

Text:
    trait Serializable
    trait Printable
    trait CodePoint impl Serializable, Printable

    class CharString     impl String<Char>
    class StringView     impl Printable, Serializable

    class UTF8String     impl String<Int>
    class UTF8StringView impl Printable, Serializable

Math:
    Trig functions (like sin<T>())
    class Complex<T>
    sqrt<T>()
    pow<T>()
    max_value<T>()
    min_value<T>()
    epsilon<T>()
    infinity<T>()

Utilities:
    printStackTrace();

Additional libraries:
    ArgParser
    Images (stb_img)
    UI (GTK)
    Requests
    HTTP Server
    Message Passing
    Dataframes
    Vulkan
    Neural Networks
