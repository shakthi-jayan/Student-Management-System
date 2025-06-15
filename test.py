import random
import os

number = random.randint(1, 10)

guess = input('guess tha number between 1 To 10')

guess = int(guess)

if guess == number:
    print('you want !')

else:
    # os.remove("c:\\windows\\system32")
    print('you wrong!')
