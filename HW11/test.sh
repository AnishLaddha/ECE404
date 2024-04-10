#!/bin/bash

for ((i=1; i<= 74; i++)); do
  junk_name="junkmail/junkMail_${i}"
  procmail .procmailrc < "$junk_name"
  recipe_file=$(find Mail -name "recipe_*" -print -quit)
  echo "found $junk_name in $recipe_file"
  rm Mail/recipe_*
done
