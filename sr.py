
# USAGE:
# py sr.py <target> <output> (<search> <replace>)*

import sys

def fopen(fname):
  with open(fname, 'r') as file:
    return file.read()

def fsave(newfname, data):
  with open(newfname, 'w') as file:
    file.write(data)

def searchReplace(terms, data):
  for search, replace in terms:
    data = data.replace(search, replace)
  return data

data = fopen(sys.argv[1])

terms = []
current = 2
while current:
  current += 1
  if current == len(sys.argv):
    break
  s = sys.argv[current]
  current += 1
  if current == len(sys.argv):
    break
  r = sys.argv[current]
  terms.append((s, r))

data = searchReplace(terms, data)

fsave(sys.argv[2], data)
