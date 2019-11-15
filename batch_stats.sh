# python3 stats.py ./apilogs/ -p
# python3 stats.py ./apilogs/ -p --ignore packed
# python3 stats.py ./apilogs/ -p --ignore dotnet nonc
# python3 stats.py ./apilogs/ -p --ignore dotnet nonc packed
# python3 stats.py ./apilogs/ -p --ignore dotnet nonc dll
# python3 stats.py ./apilogs/ -p --ignore dotnet nonc dll packed
python3 stats.py ./apilogs/ -pn
python3 stats.py ./apilogs/ -pn --min_apis 2
python3 stats.py ./apilogs/ -pn --ignore empty
python3 stats.py ./apilogs/ -pn --ignore packed
python3 stats.py ./apilogs/ -pn --ignore dotnet nonc
python3 stats.py ./apilogs/ -pn --ignore dotnet nonc packed
python3 stats.py ./apilogs/ -pn --ignore dotnet nonc dll
python3 stats.py ./apilogs/ -pn --ignore dotnet nonc dll packed
python3 stats.py ./apilogs/ -pn --ignore dotnet nonc dll packed empty
python3 stats.py ./apilogs/ -pn --ignore dotnet nonc dll packed empty --min_apis 2
