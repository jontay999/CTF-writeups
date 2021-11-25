import pexpect

def isValid(rows, cols, newRow, newCol, matrix1):
    if(0<= newRow < rows and 0 <= newCol < cols):
        if(matrix1[newRow][newCol] != '☠️'):
            return True
    return False

def bfs(matrix, start, end):
    rows = len(matrix)
    cols = len(matrix[0])
    queue = [end]
    visited = {end: None}

    while(queue):
        current = queue.pop(0)
        if current == start:
            shortest_path = []
            while current:
                shortest_path.append(current)
                current = visited[current]
            return shortest_path

        currRow, currCol = current
        for x,y in [(0,1),(1,0),(0,-1),(-1,0)]:
            newRow = currRow+x
            newCol = currCol+y
            if(isValid(rows, cols, newRow, newCol, matrix) and (newRow, newCol) not in visited):
                visited[(newRow, newCol)] = current
                queue.append((newRow, newCol))



def direction(p1, p2):
    if(p2[0] - p1[0] == 1):
        return 'D'
    if(p2[1] - p1[1] == 1):
        return 'R'
    if(p2[1] - p1[1] == -1):
        return 'L'
    if(p2[0] - p1[0] == -1):
        return 'U'
    

def getAns(input1):
    lines = input1.split('\n')
    matrix = []
    possible = ['🔩', '💎', '☠️', '🤖']
    start = (-1,-1)
    end = (-1,-1)
    for idx, i in enumerate(lines):
        cols = i.split()[1:-1]
        if(len(cols) > 0 and cols[0] in possible):
            matrix.append(cols)
    for idx, i in enumerate(matrix):
        if('🤖' in i):
            start = (idx, i.index('🤖'))
        if('💎' in i):
            end = (idx, i.index('💎'))
    result = bfs(matrix, start, end)
    finalAns = []
    for i in range(1, len(result)):
        finalAns.append(direction(result[i-1], result[i]))

    ans = ''.join(finalAns)
    return ans


analyzer = pexpect.spawn("nc 178.62.19.68 31395", encoding='utf-8')
analyzer.expect('> ')
analyzer.sendline('2')
analyzer.expect('>')

count = 0
while(True):
    m = analyzer.before
    analyzer.sendline(getAns(m))
    try:
        analyzer.expect('>')
        print(analyzer.before)
        count += 1
    except Exception:
        print(analyzer.before)
        break

    if(count  > 550):
        break