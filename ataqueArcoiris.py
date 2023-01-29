import random, string, hashlib, zlib, time

class ataqueArcoiris:

    # For the reconstructionFunction():

    dictChar = {"00000": 'a', "00001": 'b', "00010": 'c', "00011": 'd', "00100": 'e', "00101": 'f', "00110": 'g',
                "00111": 'h', "01000": 'i', "01001": 'j', "01010": 'k', "01011": 'l', "01100": 'm', "01101": 'n',
                "01110": 'o', "01111": 'p', "10000": 'q', "10001": 'r', "10010": 's', "10011": 't', "10100": 'u',
                "10101": 'v', "10110": 'w', "10111": 'x', "11000": 'y', "11001": 'z', "11010": '0', "11011": '1',
                "11100": '2', "11101": '3', "11110": '4', "11111": '5'}

    # __init__ is a special method called whenever you try to make
    # an instance of a class. As you heard, it initializes the object.
    # Here, we'll initialize some of the data.

    def __init__(self, algorithm, bits):

        self.algorithmHash = algorithm # To choose (SHA, MD5 or CRC32)
        self.bits = int(bits) # To use a determinated number of bits of hash
        #self.numexperiments = numexperiments # Number of experiments to execute
        # ¿Contraseña dificil: numeros, caracteres y eso? (Por ahora lo estoy haciendo manualmente con un input)

    def generateNewPassword(self, spacePass):

        # characters = list(string.ascii_letters + string.digits + "@!$#&%^()*") (Very difficult to attack)

        characters = list(string.ascii_lowercase) # Passwords of 5 lowercase alphabetic characters
        space_passw2 = list(string.digits + ".,:;")# Passwords of 6 characters either numeric or in the set {".", ", ", ", " : ", ";"}
        space_passw3 = list(string.digits + "aeiou")# Passwords of 6 characters either numeric or vowels

        if (spacePass == 0):
            # The length of the password.
            length_pass = 5
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

        elif (spacePass == 1):
            length_pass = 6
            random.shuffle(space_passw2)
            randompassword = []
            for i in range(length_pass):
                randompassword.append(random.choice(space_passw2))
            # Shuffling the result
            random.shuffle(randompassword)
            # Converting the list to string
            newpassword = "".join(randompassword)
        elif (spacePass == 2):
            length_pass = 6
            random.shuffle(space_passw3)
            randompassword = []
            for i in range(length_pass):
                randompassword.append(random.choice(space_passw3))
            # Shuffling the result
            random.shuffle(randompassword)
            # Converting the list to string
            newpassword = "".join(randompassword)
        else:
            raise ValueError("Mal elegido el espacio de claves de passwords. (Solo puede ser 0, 1 o 2)")

        # Returning the random password of the specified space.
        return newpassword

    def reconstructionFunction(self, hash):
        """
        dictChar = {"00000": 'a', "00001": 'b', "00010": 'c', "00011": 'd', "00100": 'e', "00101": 'f', "00110": '0',
                    "00111": '1', "01000": '2', "01001": '3', "01010": '4', "01011": '5', "01100": '6', "01101": '7',
                    "01110": '8', "01111": '9', "10000": 'a', "10001": 'b', "10010": 'c', "10011": 'd', "10100": 'e',
                    "10101": 'f', "10110": '0', "10111": '1', "11000": '2', "11001": '3', "11010": '4', "11011": '5',
                    "11100": '6', "11101": '7', "11110": '8', "11111": '9'}
        """
        lenght = int(self.bits/4)  # 10*4 = 40 bits
        #lenght = 10
        if self.algorithmHash == "crc32":
            hash = str(hash)

        hash = hash[0:lenght]

        print("Initial string(hash)", hash)

        scale = 16  # to convert hex string to integer in Python AND zfill add zeros int the left part.
        binary = bin(int(hash, scale))[2:].zfill(self.bits)
        stringres = str(binary)
        print(stringres)
        res = ""

        # Recorremos la cadena de 5 en 5
        for i in range(0, len(stringres), 5):
            x = stringres[i:i + 5]
            if x in self.dictChar:
                res = res + self.dictChar.get(x)

        return res

    def functionHash(self, password, algorithm, numBits):
        try:
            if algorithm == "crc32": # Only uses 32 bits
                hash = zlib.crc32(password.encode())
                # lenght = int(numBits / 4)  # 10*4 = 40 bits
                # hash = hash[0:lenght]
            elif algorithm == "md5":
                hash = hashlib.md5(password.encode())
                hash = hash.hexdigest()
                lenght = int(numBits / 4)  # 10*4 = 40 bits or 40/4 = 10 is the lenght
                hash = hash[0:lenght] # To truncate the hash
            elif algorithm == "sha":
                hash = hashlib.sha256(password.encode())
                hash = hash.hexdigest()
                lenght = int(numBits / 4)  # 10*4 = 40 bits
                hash = hash[0:lenght]
            else:
                raise ValueError("Mal elegido la funcion Hash. (Solo puede ser crc32, md6 o sha)")

            return hash

        except AttributeError:
            print("Password is None and cannot be encoded.")

    def ataqueArcoiris(self,t,n,spacePass):

        #t = int(input("Introduzca longitud de la secuencia(t): "))
        #n = int(input("Introduzca el número de entradas de la tabla(n): "))
        #spacePass = int(input("Introduzca el espacio de caracteres de la contraseña (0, 1 o 2): "))

        # 1: tabla = tabla vacia
        table = {}

        # 2: while La tabla no contenga n entradas do
        while len(table) < n:

            generatedPassword = self.generateNewPassword(spacePass)
            print("La contraseña generada es: " + generatedPassword)
            # 3: P = Pi
            password = generatedPassword

            for j in range(1, t):  # 4: for j = 1 to t − 1 do
                password = self.reconstructionFunction(
                    self.functionHash(password, self.algorithmHash, self.bits))  # 5: P = r(h(P))
                print("Contraseña intermedia: " + password)
            # Store <P,h(P)> in the table.
            hashP = self.functionHash(password, self.algorithmHash, self.bits)
            print("The last Hash to store in the table is: " + str(hashP))
            table[hashP] = generatedPassword

        # Require the hash of a password(p0) -> h -> r
        # Require: El resumen de un password p0 obtenido mediante la
        # función h y una función recodificante r
        # Require: Una tabla rainbow para la función h de anchura t.
        # Ensure: pwd tal que p0 = h(pwd) o ERROR

        p0 = input("Introduzca la contraseña a atacar: ")
        p0 = self.functionHash(p0,self.algorithmHash,self.bits)
        print("El resumen de un password p0 obtenido mediante la función h y una función recodificante r: " + str(p0))
        p = p0
        final = True
        for i in range(t):  # for i = 1 to t do
            if p in table.keys():  # Las claves son los hashes
                final = False
                break
            p = self.functionHash(self.reconstructionFunction(p), self.algorithmHash, self.bits)
        if final == True:
            print("ERROR")
            return "ERORR"

        pwd = table.get(p)  # La b es decir la contraseña en la que (e=p), se asigna pwd
        print("ESTO ES :" + pwd)
        while self.functionHash(pwd, self.algorithmHash, self.bits) != p0: # while h(pwd) ̸= p0 do
            #pwd = r(h(pwd))
            pwd = self.reconstructionFunction(self.functionHash(pwd, self.algorithmHash, self.bits))

        print("Se encontro la password tal q. p0 = h(pwd): " + pwd)
        return pwd

# if __name__ == "__main__":
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
