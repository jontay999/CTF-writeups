# NahamCon 2022 – Misc Challenges

## When Am I

### Description

```
When am I??

So, I look down at my watch. It's December 28, 2011 at 11:59AM, and I'm just minding my own business at -13.582075733990298, -172.5084838587106.
I hung out there until the local time was 1:00AM on December 31st, and then I hopped on a plane and took a 1 hour flight over to -14.327595989244111, -170.71287979386747.
Some time has passed since I landed, and on December 30th, 12PM local time, I took a 1 hour flight back to my original location.
It's been 10 hours since I landed on my most recent flight - how many seconds have passed since I first looked at my watch?

(Submission format is flag{<number of seconds goes here>}, such as flag{600}.)
```

### Solve

1. 12 hr 1 min to end of Dec 28
2. 24 hr to end of Dec 29
3. Note that the `-13.582075733990298, -172.5084838587106` is in Samoa which skipped 30th Dec 2011
4. 1 hr to Dec 31 1am
5. 1 hr flight to new coordinates in `Pago Pago` --> reach at 2am Dec 30th (Pago Pago is 1 day behind)
6. 10 hrs passed
7. 1 hr flight
8. 10 hr since landing
9. Note that Samoa observes daylight savings while Pago Pago does not so you have to add an extra hour
