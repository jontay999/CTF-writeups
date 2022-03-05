console.log("Whats your order sir?");

const inpBuf = Buffer.alloc(2048);
const input = inpBuf
  .slice(0, require("fs").readSync(0, inpBuf))
  .toString("utf8");

require = undefined;
module = undefined;

const flag = "REDACTED";

if (/[\'\"\`]/g.test(input)) {
  console.log("Access Denied.");
} else if (
  (() => {
    for (let i = 0; i < input.length; i++) {
      if ((input[i] ^ +[]) !== (input[i % Infinity] & 255)) {
        return true;
      }
      return false;
    }
  })()
) {
  console.log("Access Denied.");
} else {
  try {
    console.log(
      "Executing...",
      eval(`'use strict'; (() => { return 0 /* ${input} */ })()`)
    );
  } catch (error) {
    console.log("Access Denied.", error.message);
  }
}
