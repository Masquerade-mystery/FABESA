# FABESA: Fast Attribute-Based Encryption with Adaptive Security under Standard Assumption

This is the code for the paper "FABESA: Fast Attribute-Based Encryption with Adaptive Security under Standard Assumption".

This paper proposes fast ABE schemes that are adaptive secure under the Decisional Linear (DLIN) assumption. Compare to the state-of-the-art ABE schemes FAME CCS'17 [1] and FABEO'22 [2], the proposed ABE schemes are faster than FAME and very close to FABEO. Besides, the proposed ABE schemes satisfy ciphertext anonymity so they can be easily bridged to partially anonymous ABE schemes by adopting the partially hidden structure. Compare to the state-of-the-art anonymous KP-ABE schemes FEASE'24 [8], CWDWL'16 [9], and anonymous CP-ABE scheme CDWL'16 [10], the proposed anonymous KP-ABE scheme performs very close to FEASE and outperforms CWDWL'16, the proposed anonymous CP-ABE schemes surpasses CDWL'16. 

The code uses the Charm library and Python and builds upon the code of [FEASE] https://github.com/Masquerade99/FEASE.git. We provide the implementation of the following schemes:

1. FAME, CCS 2017 [1]
2. FABEO, CCS 2022 [2]
3. GPSW, CCS 2006 [3]
4. BSW, IEEE S&P 2007 [4]
5. Waters, PKC 2011 [5]
6. CGW, EUROCRYPT 2015 [6]
7. ABGW, CCS 2017 [7]
8. FEASE, USENIX 2024 [8]
9. CWDWL, IEEE TDSC 2016 [9]
10. CDWL, ProvSec 2016 [10]

All schemes are implemented using asymmetric Type-III pairing groups.

The schemes have been tested with Charm 0.50 and Python 3.9.16 on Ubuntu 22.04. (Note that Charm may not compile on newer Linux systems due to the incompatibility of OpenSSL versions 1.0 and 1.1.).


## Manual Installation

Charm 0.50 can also be installed directly from [this] (https://github.com/JHUISI/charm) page, or by running

```sh
pip install -r requirements.txt
```
Once you have Charm, run
```sh
make && pip install . && python samples/run_cp_schemes.py
```

## References

1. Cui H, Wan Z, Deng R H, et al. Efficient and expressive keyword search over encrypted data in cloud. IEEE Transactions on Dependable and Secure Computing, 2016, 15(3): 409-422.
2. Meng R, Zhou Y, Ning J, et al. An efficient key-policy attribute-based searchable encryption in prime-order groups. Provable Security: 11th International Conference, ProvSec 2017, Xi'an, China, October 23-25, 2017, Proceedings 11. Springer International Publishing, 2017: 39-56.
3. Agrawal S, Chase M. FAME: fast attribute-based message encryption. Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security. 2017: 665-682.
4. Riepel D, Wee H. FABEO: Fast Attribute-Based Encryption with Optimal Security. CCS '22: Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security, November 2022, Pages 2491–2504.
