import user
import broker
import random


try:
    while True:
        print("Assign any of the following role:")
        print("Press 1 for USER")
        print("Press 2 for Broker")
        print("Press 3 for Seller")
        
        userInp = raw_input("Enter your selection: ")
        
        if(userInp == '1'):
            brInfo = raw_input("Enter Broker's IP address & port (format: ipaddress:port): ")
            ip = brInfo.split(':')[0]
            port = int(brInfo.split(':')[1])
            id = random.randint(10,100)
            user1 = user.User(ip,port,id)
        elif(userInp == '2'):
            broker1 = broker.Broker()
        elif(userInp == '3'):
            print("Seller")
        else:
            print("Invalid Input, Try Again")
except Exception as e:
    print e