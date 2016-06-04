#!/usr/bin/env python

def fun():
    global  i
    i = 2
    print "in fun():", i

if __name__ == "__main__":
    i = 1
    print "in main():", i
    fun()
    print "in main():", i
