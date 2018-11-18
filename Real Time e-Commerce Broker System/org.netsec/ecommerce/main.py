import user
import broker
import random
import seller


try:
    while True:
        print("Assign any of the following role:")
        print("Press 1 for USER")
        print("Press 2 for Broker")
        print("Press 3 for seller")
        
        userInp = raw_input("Enter your selection: ")
        if(userInp == '1'):
            brInfo = raw_input("Enter Broker's IP address & port (format:-ipaddress:port): ")
            ip = brInfo.split(':')[0]
            port = brInfo.split(':')[1]
            id = random.randint(10,100)  # @ReservedAssignment
            user1 = user.User(ip,port,"C"+str(id))
        elif(userInp == '2'):
            broker1 = broker.Broker()
        elif(userInp == '3'):
            id = random.randint(10,100)  # @ReservedAssignment
            seller1 = seller.Seller("S"+str(id))
        else:
            print("Invalid Input, Try Again")
except Exception as e:
    print e