import random, string, hashlib, zlib, time


class AtaqueArcoiris:

    # __init__ is a special method called whenever you try to make
    # an instance of a class. As you heard, it initializes the object.
    # Here, we'll initialize some of the data.
    def __init__(self, algorithm, numexperiments, bits):
        # Let's add some data to the [instance of the] class.
        self.algorithmHash = algorithm
        self.bits = bits
        self.numexperiments = numexperiments



    def generateNewPassword(self, lenghtpass):
        # The characters to generate password (only ascii_lowercase)
        # characters = list(string.ascii_letters + string.digits + "@!$#&%^()*")

        characters = list(string.ascii_lowercase)
        # The length of the password.
        #length_pass = lenghtpass
        length_pass = 8
        # Shuffling the characters.
        random.shuffle(characters)
        # Picking random characters, from the list.
        randompassword = []
        for i in range(length_pass):
            randompassword.append(random.choice(characters))
        # Shuffling the result
        random.shuffle(randompassword)
        # Converting the list to string
        newpassword = "".join(randompassword)
        # Returning the random password.
        return newpassword


    def reconstructionFunction(self,hash):  # No se muy bien si voy bien encaminado

        dictChar = {"00000": 'a', "00001": 'b', "00010": 'c', "00011": 'd', "00100": 'e', "00101": 'f', "00110": 'g',
                    "00111": 'h', "01000": 'i', "01001": 'j', "01010": 'k', "01011": 'l', "01100": 'm', "01101": 'n',
                    "01110": 'o', "01111": 'p', "10000": 'q', "10001": 'r', "10010": 's', "10011": 't', "10100": 'u',
                    "10101": 'v', "10110": 'w', "10111": 'x', "11000": 'y', "11001": 'z', "11010": 'a', "11011": 'b',
                    "11100": 'c', "11101": 'd', "11110": 'e', "11111": 'f'}

        lenght = 10  # 10*4 = 40 bits
        hash = hash[0:lenght]

        print("Initial string", hash)

        scale = 16  # to convert hex string to integer in Python AND zfill add zeros int the left part.
        binary = bin(int(hash, scale)).zfill(8)
        stringres = str(binary)

        res = ""

        for i in range(len(stringres)):
            x = stringres[i + 4] + stringres[i + 3] + stringres[i + 2] + stringres[i + 1] + stringres[i]
            if x in dictChar:
                res = res + dictChar.get(x)
            i = i + 5

        return res


    def functionHash(self, password, algorithm, numBits):
        if algorithm == "crc32":
            hash = zlib.crc32(password.encode())
            #lenght = int(numBits / 4)  # 10*4 = 40 bits
            #hash = hash[0:lenght]
        elif algorithm == "md5":
            hash = hashlib.md5(password.encode())
            hash = hash.hexdigest()
            lenght = int(numBits / 4)  # 10*4 = 40 bits
            hash = hash[0:lenght]
        elif algorithm == "sha":
            hash = hashlib.sha256(password.encode())
            hash = hash.hexdigest()
            lenght = int(numBits / 4)  # 10*4 = 40 bits
            hash = hash[0:lenght]
        else:
            return -1

        return hash


    def ataqueArcoiris(self):

        ini_time = time.time()
        t = int(input("Introduzca longitud de la secuencia(t): "))
        n = int(input("Introduzca el número de entradas de la taba(n): "))
        lengthPassword = int(input("Introduzca la longitud de la contraseña: "))

        # 1: tabla = tabla vacia
        table = {}
        # table["1"] = "Sachin Tendulkar"

        # 2: while La tabla no contenga n entradas do
        while len(table) < n:

            generatedPassword = self.generateNewPassword(lengthPassword)
            print(generatedPassword)
            # 3: P = Pi
            password = generatedPassword

            for j in range(t-1): # 4: for j = 1 to t − 1 do
                password = self.reconstructionFunction(self.functionHash(password, self.algorithmHash, self.bits)) # 5: P = r(h(P))
            # Store <P,h(P)> in the table.
            table[self.functionHash(password, self.algorithmHash, self.bits)] = generatedPassword

        # Require the hash of a password(p0) -> h -> r
        # Require: El resumen de un password p0 obtenido mediante la
        # función h y una función recodificante r
        # Require: Una tabla rainbow para la función h de anchura t.
        # Ensure: pwd tal que p0 = h(pwd) o ERROR

        p0 = input("Introduzca el resumen de un password p0 obtenido mediante la función h y una función recodificante r ")
        p = p0
        for i in range(t):  # No lo entiendo
            if p in table.keys():  # Que es la clave y que es el valor
                break
            p = self.functionHash(self.reconstructionFunction(p), self.algorithmHash, self.bits)
        if i == t: # Tampoco entiendo esto
            return -1

        pwd = table.get(p)  # No lo entiendo, no se donde tengo que sacar la b

        while self.functionHash(pwd, self.algorithmHash, self.bits) != p0:
            pwd = self.reconstructionFunction(self.functionHash(pwd, self.algorithmHash, self.bits))

        fin_time = time.time()
        print("El tíempo de ejecución del programa " + str(fin_time - ini_time))

        return pwd


#if __name__ == "__main__":
#    main()


"""def binario_a_ascii(binario):
    # Convertir binario a decimal
    valor = int(binario, 2)
    # Convertir el decimal a su representación ASCII
    return chr(valor)

def binario_a_texto(texto_binario):
    texto_plano = ""
    for binario in texto_binario.split(separador):
        texto_plano += binario_a_ascii(binario)
    return texto_plan
"""