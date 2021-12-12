# niteCTF – Lost Dungeon 1,2

- **Category:** Reversing
- **Points:** 500, 500

## Challenge

This was actually 2 independent challenges bundled within the same file. We are given a bunch of Unity game files.

## Solution

Challenge 1

1. Playing the game for a bit on my windows VM showed that there was a very long path to a section of the map. However, I didn't think about patching/modding the game before playing it and spent a good 20 mins traersing to the location.
2. When I reached the location I was immediately surrounded by enemies, and couldn't move which wasted my time hahha
3. I used [dnsPy](https://github.com/dnSpy/dnSpy/releases) to reverse the `.dll` files. The main game files were all in `Assembly-CSharp.dll`
4. One of the classes was a `Mover` class that had some parts multiplied by `Time` which was what I figured controlled the movement speed.
5. I also disabled the collision check in order to prevent being trapped.
6. However, when I reached the same place (albeit a lot faster now), the enemies still swarmed me, the only difference was that I wasn't trapped due to collision detection being turned off.
7. Exploring the cave a bit showed that there were the characters `nite{...}` in the cave. Earlier at the spawn point, there was an NPC that mentioned that the beasts would rearrange themselves into certain characters if the curse was lifted off of them. This hinted that I had to disable the feature that caused the enemies to swarm me to see the shape
8. Looking at the `Enemy` class, I saw that there was a check for "Player" somewhere in the code. I can't really read C# well, but I just deleted that whole chunk of code hahhahah
9. When I reached back there, I found them in the characters of the flag.

Flag 1

```
nite{reply.nite@gmail.com}
```

Challenge 2

1. The prompt was that we had to somehow get to the secret level.
2. Some of the NPCs mentioned that the "portal" would only open for wizards.
3. Taking a look at the `Portal` class showed that there was a check for the player's name as "wizard". Following that, a random scene would be loaded from (2, length of total scenes). Changing the scene loaded to `this.scenes[0]` led to us entering the secret level
4. However the NPCs there mentioned that we had to change our respawn point.
5. Taking a look at the `GameObject` Class I realised that the character spawned at "RespawnPoint" and that there was another function that when called would spawn the character at "SpawnPoint"
6. Changing the spawn point led to the flag

Flag 2

```
nite{}
```

## Thoughts

- Honestly a very frustrating yet gratifying challenge to complete
- Never thought a reversing challenge could be about Unity files, gave me some fun in fiddling about with the game controls.
