arr =  [ 
    [81, 107, 33, 120, 172, 85, 185, 33],
    [154, 254, 232, 3, 171, 171, 16, 29, 111, 228, 232, 245, 111, 89, 158, 219, 24, 210, 111, 171, 172, 219, 210, 46, 197, 76, 167, 233],
    [215, 11, 59, 120, 237, 146, 94, 236, 11, 250, 33, 198, 198],
    [59, 185, 46, 236, 33, 42, 33, 162, 223, 219, 162, 107, 250, 81, 94, 46, 159, 55, 172, 162, 223, 11]
]

def q(array):
    result = ""
    for i in array:
        result += chr((i*59-54)&255)
    return result

for i in arr:
    print(q(i))
