TOKEN = b'd4r3d3v!l'
def chall():
    s = Sign()
    while True:
        choice = input("> ").rstrip()
        if choice == 'P':
            print("\nN : {}".format(hex(s.n)))
            print("\ne : {}".format(hex(s.e)))
        elif choice == 'S':
            try:
                msg = bytes.fromhex(input('msg to sign : '))
                if TOKEN in msg:
                    print('[!] NOT ALLOWED')
                else:
                    m = bytes_to_long(msg)
                    print("\nsignature : {}".format(hex(s.sign(m))))      #pow(msg,d,n)
                    print('\n')
            except:
                print('\n[!] ERROR (invalid input)')
                
        elif choice == 'V':
            try:

                msg = bytes.fromhex(input("msg : "))
                m = bytes_to_long(msg)
                signature = int(input("signature : "),16)
                if m < 0 or m > s.n:
                    print('[!] ERROR')
                
                if s.verify(m, signature):                           #pow(sign, e, n) == msg
                    if long_to_bytes(m) == TOKEN:
                        print(SECRET)
                
                    else:
                        print('\n[+] Valid signature')
                       
                else:
                    print('\n[!]Invalid signature')
   
            except:
                print('\n[!] ERROR(invalid input)')


        elif choice == 'Q':
            print('OK BYE :)')
            exit(0)
        else:
            print('\n[*] SEE OPTIONS')