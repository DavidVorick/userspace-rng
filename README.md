# userspace-random

userspace-random is a rust crate that is intended to provde secure entropy to
the caller even if the operating system entropy is not secure.

Modern operating systems like Linux, Mac, and Windows will all provide reliable
entropy, however more niche operating systems and environments often will
provide broken RNGs to the user. This concern is especially acute in IoT and
embedded hardware, where the engineers are deliberately taking as many
shortcuts as they can to trim down the operating system and hardware
requirements. The result may be an unintentionally compromised operating system
RNG without any of the software realizing that the RNG is compromised.

This worry has precedent. When Android was newer, a broken RNG in Android put
user funds at risk: https://bitcoin.org/en/alert/2013-08-11-android

To protect users against insecure hardware, we developed a library that
generates reliable entropy in userspace. We have constructed the library to
ensure that the randomness can only be compromised if both the operating system
RNG is broken and also the assumptions made by our library are incorrect.

Had the Android wallets used userspace-random to generate their entropy, user
funds likely would have been safe despite the flaw in Android itself.

## Construction

This library draws entropy from CPU jitter. Specifically, the number of
nanoseconds required to complete a cryptographic hash function has a high
amount of variance. My own testing suggested that under normal circumstances
the variance is around 100ns with a standard deviation of around 40ns. This
suggests that using time elapsed during a cryptographic hashing function as a
source of entropy will provide between 4 and 6 bits of entropy per measurement.

When the library starts up, it performs 25 milliseconds of hashing, performing
a strict minimum of 512 hashing operations total. This theoretically provides
more than 2000 bits of entropy, which means there is a comfortable safety
margin provided by the library. Even hardware that is more stable and reliable
should be producing at least 1/4 bits of entropy per hash operation owing to
the natural physical limitations of CPUs.

To give some brief intuition: a CPU is a physical device that consumes
electricity and produces heat. The speed at which a CPU operates (at least,
with our current technology) is surprisingly dependent on factors like voltage
and temperature. Further, these factors tend to vary rapidly as a CPU performs
computations. Empirical measurements demonstrate that the variance is
sufficiently significant to cause material variance in the total execution time
of a cryptographic hash operation. Other factors such as background activity by
the operating system can also play a role.

For fun, this library also incorporates some ideas from the fortuna paper to
protect users against an adversary that has the ability to use side channels to
compromise the user entropy. In reality, these extra choices are probably not
necessary to protect against real-world attackers. Fortuna was designed with a
very different threat model in mind than the one we face with this library.

Fortuna paper: https://www.schneier.com/wp-content/uploads/2015/12/fortuna.pdf
