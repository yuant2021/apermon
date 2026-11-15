#!/usr/bin/env bash


[[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]] && {
    echo 'error: missing env'
    exit 1
}

cd "`dirname "$0"`"

# monospace keeps the summary columns aligned; AS names may contain "&", "<" or ">".
text="`./summary.sh | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'`"

curl -s "https://api.telegram.org/$BOT_TOKEN/sendMessage" -d "chat_id=$CHAT_ID" -d "parse_mode=HTML" --data-urlencode "text=<pre>$text</pre>"