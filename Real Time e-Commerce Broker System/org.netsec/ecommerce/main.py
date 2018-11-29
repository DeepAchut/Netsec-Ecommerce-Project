import user
import broker
import seller


try:
    while True:
        print("Assign any of the following role:")
        print("Press 1 for Buyer")
        print("Press 2 for Broker")
        print("Press 3 for Seller")
        
        userInp = raw_input("Enter your selection: ")
        if(userInp == '1'):
            brInfo = raw_input("Enter Broker's IP address & port (format:-ipaddress:port): ")
            ip = brInfo.split(':')[0]
            port = brInfo.split(':')[1]
            user1 = user.User(ip,port)
        elif(userInp == '2'):
            broker1 = broker.Broker()
        elif(userInp == '3'):
            seller1 = seller.Seller()
        else:
            print("Invalid Input, Try Again")
except Exception as e:
    print e