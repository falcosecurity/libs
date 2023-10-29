// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <iostream>
#include <cstdint>
#include <cmath>
#include <vector>
#include <algorithm>
#include "xxhash_ext.h"

/*

"MVP CountMinSketch Powered Probabilistic Counting and Filtering"

To be explored:

- Log scale conversions of counts
- Conservative Updates
- CountMikSketch variations or augmentations that can be found in the literature
- Cache of topK hitters (e.g. could also serve as generalization of suppressed comms etc)

Literature:

- Bigger Vision for Threat Detection: See Falco Proposal PR https://github.com/falcosecurity/falco/pull/2655
- [Count-Min sketch blog 1](https://towardsdatascience.com/big-data-with-sketchy-structures-part-1-the-count-min-sketch-b73fb3a33e2a)
- [Count-Min sketch blog 2](https://www.synnada.ai/blog/probabilistic-data-structures-in-streaming-count-min-sketch)
- [Probabilistic Data Structures and Algorithms
for Big Data Applications](https://www.gakhov.com/books/pdsa.html) book
- [Count-Min-Log sketch](https://arxiv.org/pdf/1502.04885.pdf) paper
- [Count-Min Sketch with Conservative Updates](https://hal.science/hal-03613957/document#:~:text=Count%2DMin%20Sketch%20with%20Conservative%20Updates%20(CMS%2DCU),because%20of%20its%20inherent%20difficulty) paper
- https://github.com/Cyan4973/xxHash as new dependency for fast and reliable hashing (using xxh3)

*/

namespace libsinsp {
namespace num {

template<typename T>
class cms {
private:
    T** sketch;
    uint64_t d; // d / Rows / number of hash functions
    uint64_t w; // w / Cols / number of buckets

public:
    cms(double gamma, double eps) {
        d = static_cast<uint64_t>(std::ceil(std::log(1.0 / gamma))); // Error probability (e.g. 0.001) -> determine d / Rows / number of hash functions
        w = static_cast<uint64_t>(std::ceil(std::exp(1) / eps)); // Relative error (e.g. 0.0001) -> determine w / Cols / number of buckets
        sketch = new T*[d];
        for (uint64_t i = 0; i < d; ++i) 
        {
            sketch[i] = new T[w];
        }
        // Init to 0
        for (uint64_t i = 0; i < d; ++i) {
            std::fill(sketch[i], sketch[i] + w, (T)0);
        }
    }

    ~cms() {
        for (uint64_t i = 0; i < d; ++i) 
        {
            delete[] sketch[i];
        }
        delete[] sketch;
    }

    uint64_t hash_XXH3_seed(std::string value, uint64_t seed) const {
        // using https://raw.githubusercontent.com/Cyan4973/xxHash/v0.8.2/xxhash.h
        // Requirement: Need fast and reliable independent hash functions.
        uint64_t hash = XXH3_64bits_withSeed(value.c_str(), value.size(), seed);
        return hash;
    }

    void update(std::string value, T count) {
        // Update counts for each hash function.
        // Note: d is typically very small (e.g. < 10)
        for (uint64_t seed = 0; seed < d; ++seed)
        {
            // Map the hash value to an index of the current sketch Row by taking the modulo of the hash value, where w is the number of buckets.
            // Simply loop over d, which is the number of hash functions, to obtain a seed in order to use independent hash functions for each Row.
            sketch[seed][hash_XXH3_seed(value, seed) % w] += count;
        }
    }

    T update_estimate(std::string value, T count) const {
        std::vector<T> estimates;
        // Same as the update function, but also returns the minimum count as an estimate.
        // Note: d is typically very small (e.g. < 10)
        for (uint64_t seed = 0; seed < d; ++seed)
        {
            T index = hash_XXH3_seed(value, seed) % w;
            sketch[seed][index] += count;
            estimates.push_back(sketch[seed][index]);
        }
        auto min_element = std::min_element(estimates.begin(), estimates.end());
        return min_element != estimates.end() ? *min_element : T();
    }

    T estimate(std::string value) const {
        std::vector<T> estimates;
        // Return the minimum count across hash functions as an estimate.
        // Note: d is typically very small (e.g. < 10)
        for (uint64_t seed = 0; seed < d; ++seed)
        {
            T index = hash_XXH3_seed(value, seed) % w;
            estimates.push_back(sketch[seed][index]);
        }
        auto min_element = std::min_element(estimates.begin(), estimates.end());
        return min_element != estimates.end() ? *min_element : T();
    }

    T get_item(uint64_t row, uint64_t col) const {
        if (row >= 0 && row < d && col >= 0 && col < w) 
        {
            return sketch[row][col];
        } else 
        {
            return T();
        }
    }

    size_t get_size_bytes() const {
        return d * w * sizeof(T);
    }

    std::pair<uint64_t, uint64_t> get_dimensions() const {
        return std::make_pair(d, w);
    }

    uint64_t get_d() const {
        return d;
    }

    uint64_t get_w() const {
        return w;
    }

    cms(cms&&) noexcept = default;
	cms(const cms&) = default;
	cms& operator=(cms&&) noexcept = default;
	cms& operator=(const cms&) = default;
	cms() = delete;
};

}
}
