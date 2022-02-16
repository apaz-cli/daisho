
# Table of Contents

Collections:
    trait Iterable<T>
    trait RandomIterable<T>

    trait Iterator<T>
    trait RandomIterator<T>

    trait Stream<T>

    class Array<T, size_t size> impl Slice
    class NDArray<T, size_t dims...> impl Slice
    trait List<T> impl RandomIterable
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
    malloc(), realloc(), calloc(), free()

Text:
    trait Serializable
    trait Printable
    trait Stringlike

    class StringView impl Slice
    class String impl Slice
    class UTF8String

Math:
    Trig functions
    class Complex<T>
    sin<T>(), cos<T>(), tan<T>()
    sqrt<T>()
    pow<T>()
    max_value<T>()
    min_value<T>()
    epsilon<T>()
    infinity<T>()

Utilities:

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
