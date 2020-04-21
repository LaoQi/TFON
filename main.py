import hashlib


def main():
    x = hashlib.sha512(b"init")
    for i in range(5):
        b = x.digest()
        print(b.hex())
        x.update(b)

    b = x.digest()
    print(b.hex())


if __name__ == '__main__':
    main()
