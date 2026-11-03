for i in 1 2 3; do
    dig @127.0.0.1 -p 1053 google.com A
done

for i in 1 2 3; do
    dig @127.0.0.1 -p 1053 www.github.com CNAME
done