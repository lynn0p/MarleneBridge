#ifndef UTIL_H
#define UTIL_H

namespace Utility {
    static inline unsigned long long ToSatoshis(double amount)
    {
        return (unsigned long long)(amount * 1e8 + (amount < 0.0 ? -.5 : .5));
    }

    static inline double FromSatoshis(unsigned long long amount)
    {
        return ((double)amount / 1e8);
    }
}

#endif // UTIL_H
