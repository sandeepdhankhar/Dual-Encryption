# Dual-Encryption
This is a sample code to encrypt user related information in memory with unique keys for every user

Problem Statement:

A lot of times we keep things in the memory for better performance and  user experience. What if if the requirement  is to encrypt all that information in memory for some reasons ?

There could be two possible scenarios:

1. The encryption keys are on a different system other than the one holding the data.
      This scenario makes sense because encryption and decryption are done on fly on the machine which has the key. There is still a degree of vulnerability since all the data is encrypted with single key.


2. The keys are on the same system along with the data
      Any sane developer would argue that there is no point of locking the door if the key is right next to it. This very case is almost the same.



Solution:

(Disclaimer - There is nothing fancy of complicated about this solution)       

You try to avoid implementing something which is fundamentally wrong and thats when you think about other possible alternatives. This is one of such alternatives. The idea is to use sessionId of the user as a secondary key to encrypt and decrypt the user data. The session identifier (cookie) is stored on the browser side and available only when there is a request  from the user browser. This way the chances of data being compromised in memory are way less than using only single encryption key.
