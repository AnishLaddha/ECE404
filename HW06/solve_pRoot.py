def solve_pRoot(p, x): 
	'''
	Implement binary search to find the pth root of x. The logic is as follows:
	1). Initialize upper bound to 1
	2). while u^p <= x, increment u by itself
	3). Intialize lower bound to u//2
	4). While the lower bound is smaller than the upper bound:
        a). Compute the midpoint as (lower + upper) / 2
        b). Exponentiate the midpoint by p
        c). if lower bound < midpoint and midpoint < x, then set the new lower bound to midpoint
        d). else if upperbown > midpoint and midpoint > x, then set the new upper bown to midpoint
        e). else return the midpoint
	5). If while loop breaks before returning, return midpoint + 1

	Author: Joseph Wang
		wang3450 at purdue edu

	'''

	u = 1
	while u ** p <= x: u *= 2

	l = u // 2
	while l < u:
		mid = (l + u) // 2
		mid_pth = mid ** p
		if l < mid and mid_pth < x:
			l = mid
		elif u > mid and mid_pth > x:
			u = mid
		else:
			return mid
	return mid + 1