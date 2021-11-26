# G07_C00K3D Writeup

## Info

Category: Web <br/>
Difficulty: Easy

<br/>

### **tl;dr**

Change cookie for admin to true.
<br /><br />

## Initial

We are given a site that shows a username and password with a GET FLAG button
<br/>

![Start](./images/1.png)

## Method

Clicking on GET FLAG sent me to this page which hinted at becoming Admin. Upon checking the cookies, I noticed there was a cookie called Admin set to false.
<br/>

![Cookie](./images/2.png)

After changing it to true, and refreshing.
![Flag](./images/3.png)
The flag was found.

<br/>

## Thoughts

- Very basic challenge but good to get warmed up.
