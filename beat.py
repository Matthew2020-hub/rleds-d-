if __name__ == '__main__':
    n = int(input())
    arr = map(int, input().split())
    are = set(arr)
    are.sort()
    print(are[-3:-2])
   
