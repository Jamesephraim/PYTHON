
class A:
    def __init__(self):
        print("Class A")
    def add(self,x,y):
        print(x+y)
    def mul(self,x,y):
        print(x*y)
    def div(self,x,y):
        print(x/y)
        print(x//y)
 
a=A()
a.add(10,90)
a.mul(10,90)
a.div(90,10)