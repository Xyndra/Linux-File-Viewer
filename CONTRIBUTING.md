# Running

I recommend always using release mode since it 10x speeds up luks2 decryption (50 to 5 seconds on my PC)

# Adding stuff

If you create a PR, I will just check whether it seems somewhat safe, and test it on my machine. 
This means that your stuff might break in future updates, so I recommend keeping your own fork around.

If something is not working, I also won't know why. You can still create issues, but I would recommend
instead simply cloning it onto your local machine and letting an AI debug and fix it. I personally used
Claude Sonnet 4.5 and Opus 4.5 and 4.6 to create this in half a day, so I would not know more than any
AI that reads the code.
