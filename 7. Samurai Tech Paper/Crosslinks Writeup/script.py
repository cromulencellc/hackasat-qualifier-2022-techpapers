from skyfield.api import EarthSatellite, load

ts = load.timescale()
t = ts.tt(2022,1,26,11,16,15.3133515)


sat113 = EarthSatellite(
        '1 42803U 17039A   22026.37842744  .00000117  00000+0  34783-4 0  9995',
        '2 42803  86.3963 271.8702 0001790  92.5950 267.5451 14.34218082241457'
        )
sat118 = EarthSatellite(
        '1 42807U 17039E   22026.52138185  .00000115  00000+0  34026-4 0  9991',
        '2 42807  86.3982 303.3777 0002017  76.5922 283.5498 14.34216135240230'
)
sat136 = EarthSatellite(
        '1 42962U 17061H   22026.39161228  .00000118  00000+0  35184-4 0  9996',
        '2 42962  86.3998 335.0426 0001813  83.2278 276.9124 14.34219752225103'
        )

satellites = load.tle_file('./TLE')

print("# Distances Required\n# 113 3889.8015318643374\n# 118 3777.9388827598186\n# 136 3216.8770363989834")

for sat in satellites:
    pos1 = sat113.at(t) 
    pos2 = sat118.at(t)
    pos3 = sat136.at(t)
    pos4 = sat.at(t)
    if 3500 <= (pos4 - pos1).distance().km  <= 4200:
        print(sat.name)
        print("d to 113: ", (pos4 - pos1).distance().km)
        print("d to 118: ", (pos4 - pos2).distance().km)
        print("d to 136: ", (pos4 - pos3).distance().km)





