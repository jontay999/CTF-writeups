# Misc - Logical Computers (456)

## Challenge

```python
import torch

def tensorize(s : str) -> torch.Tensor:
  return torch.Tensor([(1 if (ch >> i) & 1 == 1 else -1) for ch in list(map(ord, s)) for i in range(8)])

class NeuralNetwork(torch.nn.Module):
  def __init__(self, in_dimension, mid_dimension, out_dimension=1):
    super(NeuralNetwork, self).__init__()
    self.layer1 = torch.nn.Linear(in_dimension, mid_dimension)
    self.layer2 = torch.nn.Linear(mid_dimension, out_dimension)

  def step_activation(self, x : torch.Tensor) -> torch.Tensor:
    x[x <= 0] = -1
    x[x >  0] = 1
    return x

  def forward(self, x : torch.Tensor) -> int:
    x = self.layer1(x)
    x = self.step_activation(x)
    x = self.layer2(x)
    x = self.step_activation(x)
    return int(x)

flag = input("Enter flag: ")
in_data = tensorize(flag)
in_dim	= len(in_data)

model = NeuralNetwork(in_dim, 1280)
model.load_state_dict(torch.load("model.pth"))

if model(in_data) == 1:
	print("Yay correct! That's the flag!")
else:
	print("Awww no...")

```

We are given a trained model in `model.pth` which will predict whether the string passed in is the flag and the architecture of the model. The goal is to get the output of `layer2` to be greater than 0, then the final `step_activation` layer would give a `1`

```python
def step_activation(self, x : torch.Tensor) -> torch.Tensor:
    x[x <= 0] = -1
    x[x >  0] = 1
    return x
```

At first I struggled with trying to calculate the loss to do some sort of backward gradient descent, but a simpler method occurred to me. The base concept is that the closer the `input` is to the flag, the greater the result of `layer2` will be (approaching > 0 which would be the flag). In that case, we can just try brute force each character of the flag, and calculate which character would produce a `layer2` output that is the largest and we can get the flag.

The first step is to learn the input length that can be passed in, and trying `model(tensorize(guess))` will give us a flag length of `20`, other lengths would give an error.

Because we know the flag is in the format `grey{...}`, we only have 14 characters to brute force. I run the brute force twice to refine the final flag and we get the final flag.

Note: I had to refine the Neural Network class implementation slightly to return me the output of `layer2` instead.

## Solution (Full output in [solve.ipynb](./solve.ipynb))

```python
import torch

def tensorize(s : str) -> torch.Tensor:
  return torch.Tensor([(1 if (ch >> i) & 1 == 1 else -1) for ch in list(map(ord, s)) for i in range(8)])

class NeuralNetwork(torch.nn.Module):
  def __init__(self, in_dimension, mid_dimension, out_dimension=1):
    super(NeuralNetwork, self).__init__()
    self.layer1 = torch.nn.Linear(in_dimension, mid_dimension)
    self.layer2 = torch.nn.Linear(mid_dimension, out_dimension)

  def step_activation(self, x : torch.Tensor) -> torch.Tensor:
    x[x <= 0] = -1
    x[x >  0] = 1
    return x

  def forward(self, x : torch.Tensor) -> int:
    x = self.layer1(x)
    x = self.step_activation(x)
    x = self.layer2(x)
    res = int(x)
    x = self.step_activation(x)
    return int(x), res

model = NeuralNetwork(in_dim, 1280)
model.load_state_dict(torch.load("model.pth"))

import string
alphabet = list(string.printable)
flag = ''

print("Round 1:\n")

length = 13
for j in range(length+1):
    for i in alphabet:
        guess = 'grey{' + flag + i +  'a'* (length - len(flag)) + '}'
        assert len(guess) == 20
        tensor = tensorize(guess)
        preds = model(tensor)
        arr.append((preds[1], i))
    arr = sorted(arr, reverse=True)[:6]
    flag += arr[0][1]
    print(flag)

print("\nRound 2 :\n")


guess = list('grey{' + flag + '}')
flag = ''

for j in range(len(guess)):
    arr = []
    temp = guess[:]
    for i in alphabet:
        temp[j] = i
        new_guess = ''.join(temp)
        tensor = tensorize(new_guess)
        preds = model(tensor)
        arr.append((preds[1], i))
    arr = sorted(arr, reverse=True)[:6]
    flag += arr[0][1]
    print(flag)


```

## Flag

```
grey{sM0rT_mAch1nE5}
```
