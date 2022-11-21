
# LA OPCION DE LO DE LA CONTRASEÑA DIFICIL Y TO ESO
import getopt,sys

def help():
    print("Diplaying Help. Options available")
    print("python {*.py} -h --Help  => Display Help ")
    print("python {*.py} -a --Algorithm  => Choose the Hash Algorithm, only valid these values (crc32,md5,sha) (Default: sha)")
    print("python {*.py} -n --NumberExperiments  => The number of experiments to do. (Default: 20)")
    print("python {*.py} -b --BitsHash  => The number of bits of Hash to use. (Default: 32)")
    print("Obligatory to use the following arguments: -anb")


#def main():
argumentList = sys.argv[1:]

# Options (anb requires an argument, thats why it has :)
options = "ha:n:b:"

# Long options : 'period=' requires an argument, so it has = suffixed
long_options = ["help", "Help", "Algorithm=","algorithm=", "Experiments=", "experiments=", "Bits Hash= ", "bits=", "bitsHash=",""]

try:

    if (len(sys.argv) == 1):
       help()
       raise ValueError("Se requieren más argumentos")

    arguments, values = getopt.getopt(argumentList, options, long_options)

    # list of options tuple (opt, value)
    print('Options Tuple is {}'.format(arguments))

    # list of remaining command-line arguments
    print('Additional Command-line arguments list is {}'.format(values))

    # Checking each argument
    for currentArgument, currentValue in arguments:
        currentArgument = currentArgument.lower()  # Converting all options to lowercase
        print(currentArgument)

        if currentArgument in ("-h", "--help"):
            help()
        elif currentArgument in ("-a", "--algorithm"):
            algorithm = currentValue.lower()
            if algorithm == "crc32":
                    print("You can become a web developer.")
            elif algorithm == "sha":
                    print("You can become a Data Scientist")
            elif algorithm == "md5":
                    print("You can become a backend developer")
            else:
                    raise ValueError("The algorithm was not found. (only is valid crc32,md5,sha)")
            print("Algorithm used:", algorithm)
        elif currentArgument in ("-n", "--numberexperiments"):
            if not currentValue.isnumeric():
                raise TypeError('Work with Positive Numbers Only')
            print(("Number of experiments to do: (% s)") % (currentValue))

        elif currentArgument in ("-b", "--bitshash"):
            if not currentValue.isnumeric():
                raise TypeError('Work with Numbers Only')
            print(("Number of Bits of Hash to use: (% s)") % (currentValue))

except getopt.error as err:
    print(str(err))
    help()

#if __name__ == "__main__":
 #   main()
