# SingleEventUpset - HAS3 Qualification Event Technical Paper

## I Can Haz Satellite - Fun in the Sun

```
Our solar panels are looking to get a good tan

Ticket
Present this ticket when connecting to the challenge:
ticket{mike337256whiskey3:GGJd8pQeDiOZplzXn3f23iHnG3g2NRZ7-wkX-KPk0ZntB_htOCn0hJs4S2m28k0BJA}
Don't share your ticket with other teams.

Connecting
Connect to the challenge on:
sunfun.satellitesabove.me:5300

Using netcat, you might run:
nc sunfun.satellitesabove.me 5300

Files
You'll need these files to solve the challenge.

https://static.2022.hackasat.com/820ymvp1fbgm013ilhgjp0k4wc9l
https://static.2022.hackasat.com/a7v6hb6ft6a7ooisr4wzgiv7hw6v
```

We loaded the two files we were given (de440s.bsp for planetary orbits and sat.tle for the satellite orbit) into the skyfield python library.

```python
planets = load('../de440s.bsp')
sun, earth = planets['sun'], planets['earth']
sat = load.tle_file('../sat.tle')[0]
```

From there we were able to determine the individual position vectors for the sun, earth, and satellite at the specified time. Since the satellite position vector was relative to the earth we added it to the earth’s position vector to get the satellite’s position vector relative to the sun. Then we subtracted the sun’s position vector to get a vector describing the relative difference in position between the sun and the satellite.

```python
time = load.timescale().from_datetime(datetime.fromisoformat('2022-05-21 14:00:00+00:00'))
vec = np.array((earth + sat - sun).at(time).position.km)
```

From there we converted the relative position vector into a quaternion which would describe the needed rotation to point the satellite at the sun. 

```python
def to_quat(vec):
    v1 = [0,0,1]
    v2 = vec
    x, y, z = np.cross(v1, v2)
    w = 1 + np.dot(v1, v2)
    v3 = [x, y, z, w]
    norm_len = np.sum([_i**2 for _i in v3])
    norm_sf = 1 / np.sqrt(norm_len)
    return [norm_sf * _i for _i in v3]

vec = vec / np.linalg.norm(vec)
quat = to_quat(vec)
```

When we passed this resulting quaternion to the challenge server we got a response that we were off by 90 degrees (which was a very promising response). We figured we just needed to point the correct side of the satellite at the sun. We began rotating our quaternion by 90 degrees over different axes until we found the correct one.

```python
rotation = R.from_euler('y', -90, degrees=True)
r_quat = R.from_quat(quat)
quat = (r_quat * rotation).as_quat()
```
