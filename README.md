本周还是刷题，深入学习了winner攻击以及extend winner attack.然后就是做了几个有关造格子的题，没学很多，挺忙的。
直接从博客复制过来的，格式和markdown显示有点问题，更多可以看博客 www.zbc53.top
1.mrctf[friendly_sign-in]
![2021-04-11T10:22:32.png][1]

意思就是服务器产生一个数组$N$,需要输入一个数组$X$与其对应位置乘积和为$0$,题目说$N$中全为素数，实际好像不是，因为产生这么多素数比较耗时间，但里面还是大部分都是素数。这里可以利用里面任意两个素数$N_i,N_j$，用扩展欧几里得算法求到满足$x_i*N_i+x_j*N_j=1$的$x_i,x_j$的值，设
$C=\sum\limits_{k=0}^{len(N)-1}N_k(k\ne i\ne j)$,那么$C*x_i*N_i+C*x_j*N_j=C$,即$C*x_i*N_i+C*x_j*N_j+\sum\limits_{i=1}^{len(N)-1}(-1)N_i(i\ne i\ne j)=0$,就是说数组$X$对应$i,j$位置为$x_i,x_j$,其余全为$-1$,即可满足。
选择不同的素数对，传$len(N)$次得到$flag$所有比特位。
刚开始的$pow$验证，只要满足$sha512$后开头是$11111$就行，这里选择的爆破四位。
    import hashlib
    from gmpy2 import *
    import string
    from Crypto.Util.number import *
    from pwn import *

    #context.log_level='debug'
    p=remote("node.mrctf.fun",10007)

    def solve1(s):
        flag=0
        dic=string.ascii_letters + string.digits
        for i in dic:
            for j in dic:
                for x in dic:
                    for y in dic:
                        c=s+i+j+x+y
                        c=hashlib.sha512(c.encode()).hexdigest()
                        if c[:5]=="11111":
                            flag=1
                            return i+j+x+y
                            break
                    if flag:
                        break
                if flag:
                    break
            if flag:
                break
    p.recvuntil("SHA512(\"")
    s=p.recv(8)
    p.sendline(solve1(s.decode()))
    n=""
    p.recvuntil("N = [")
    n+=p.recvuntil("]").decode()
    N=[]
    for i in n.split(","):
        N.append(int(i.strip("]")))

    flag=""
    FLAG=0
    for i in range(len(N)):
        for j in range(len(N)):
            if i<j and gcd(N[i],N[j])==1:
                first=N[i]
                Las=N[j]
                s,a,b=gcdext(first,Las)
                sum=0
                for index in range(0,len(N)):
                    if index !=i and index !=j:
                        sum+=N[index]
                answer=[-1 for _ in range(len(N))]
                answer[i]=a*sum
                answer[j]=b*sum
                for k in answer:
                    p.sendline(str(k))
                try:
                    p.recvuntil("gift: ")
                    flag+=p.recv(1).decode()
                    FLAG+=1
                except:
                    pass
            if FLAG==len(N)-1:
                break
                
        if FLAG==len(N)-1:
            break
                     
    print(long_to_bytes(int(flag,2)))
    #MRCTF{e@3y_ch3ck_1n_pr0bl3m}


  [1]: /usr/uploads/2021/04/4290365254.png
  随机数还能预测和逆向？梅森旋转算法是一种伪随机数发生算法，是R、Python、Ruby、IDL、Free Pascal、PHP、Maple、Matlab、GNU多重精度运算库和GSL的默认伪随机数产生器。
-----------

 - 获得基础的梅森旋转链
 - 对于旋转链进行旋转算法
 - 对于旋转算法所得的结果进行处理
python伪代码:
    def _int32(x):
        return int(0xFFFFFFFF & x)

    class MT19937:
        # 根据seed初始化624的state
        def __init__(self, seed):
            self.mt = [0] * 624
            self.mt[0] = seed
            self.mti = 0
            for i in range(1, 624):
                self.mt[i] = _int32(1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

        # 提取伪随机数
        def extract_number(self):
            if self.mti == 0:
                self.twist()
            y = self.mt[self.mti]
            y = y ^ y >> 11
            y = y ^ y << 7 & 2636928640
            y = y ^ y << 15 & 4022730752
            y = y ^ y >> 18
            self.mti = (self.mti + 1) % 624
            return _int32(y)

        # 对状态进行旋转
        def twist(self):
            for i in range(0, 624):
                y = _int32((self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7fffffff))
                self.mt[i] = (y >> 1) ^ self.mt[(i + 397) % 624]

                if y % 2 != 0:
                    self.mt[i] = self.mt[i] ^ 0x9908b0df

首先说明:运算符优先级:$>>\:\&\:\oplus$
1.逆向$extract\_number$函数：
$y_1 = y \oplus y>> 18$，那么显然$y_1$的高$18$位是$y$的高18位，$y$高$18$位右移与$y$低$18$位异或得到$y_1$的低$18$位，那么就可以得到$y$的高$36$位，以此类推。在有限步内就可完成还原。
    o = 99999999999999999999999999999999999999
    y = o^o>>18
    # 控制位移的次数
    for i in range(len(bin(o)[2:])//18):
        y = y^(y>>18)
    print(y==o)
    #True
继续$y_1 = y \oplus y << 15 \& 4022730752$,掩码实际上并没有起到太大作用，。。。。
    o = 99999999999999999999
    y = o ^ o << 15 & 4022730752
    tmp = y
    for i in range(len(bin(o)[2:]) // 15):
        y = tmp ^ y << 15 & 4022730752
    print(y==o)
    #True
剩下的两个完全相同方法分析。
最终得到完整的逆$extract\_number$函数的代码：
    o = 9999999999999999999999999999999999999999999999999999999999999

    # right shift inverse
    def inverse_right(res, shift):
        tmp = res
        bits=len(bin(res)[2:])
        for i in range(bits // shift):
            tmp = res ^ tmp >> shift
        return tmp


    # right shift with mask inverse
    def inverse_right_mask(res, shift, mask):
        tmp = res
        bits=len(bin(res)[2:])
        for i in range(bits // shift):
            tmp = res ^ tmp >> shift & mask
        return tmp

    # left shift inverse
    def inverse_left(res, shift):
        tmp = res
        bits=len(bin(res)[2:])
        for i in range(bits // shift):
            tmp = res ^ tmp << shift
        return tmp


    # left shift with mask inverse
    def inverse_left_mask(res, shift, mask):
        tmp = res
        bits=len(bin(res)[2:])
        for i in range(bits // shift):
            tmp = res ^ tmp << shift & mask
        return tmp


    def extract_number(y):
        y = y ^ y >> 11
        y = y ^ y << 7 & 2636928640
        y = y ^ y << 15 & 4022730752
        y = y ^ y >> 18
        return y

    def recover(y):
        y = inverse_right(y,18)
        y = inverse_left_mask(y,15,4022730752)
        y = inverse_left_mask(y,7,2636928640)
        y = inverse_right(y,11)
        return y

    y = extract_number(o)
    print(recover(y) == o)
    #True
2.预测随机数:
基于逆向$extract\_number$函数,只要有前$624$个数，由此求到对应的$state$，就可以实现预测。
    from random import Random

    o = 9999999999999999999999999999999999999999999999999999999999999
    # right shift inverse
    def inverse_right(res, shift):
        tmp = res
        bits=len(bin(res)[2:])
        for i in range(bits // shift):
            tmp = res ^ tmp >> shift
        return tmp
      
    # right shift with mask inverse
    def inverse_right_mask(res, shift, mask):
        tmp = res
        bits=len(bin(res)[2:])
        for i in range(bits // shift):
            tmp = res ^ tmp >> shift & mask
        return tmp
     
    # left shift inverse
    def inverse_left(res, shift):
        tmp = res
        bits=len(bin(res)[2:])
        for i in range(bits // shift):
            tmp = res ^ tmp << shift
        return tmp
     
    # left shift with mask inverse
    def inverse_left_mask(res, shift, mask):
        tmp = res
        bits=len(bin(res)[2:])
        for i in range(bits // shift):
            tmp = res ^ tmp << shift & mask
        return tmp
     
    def recover(y):
        y = inverse_right(y,18)
        y = inverse_left_mask(y,15,4022730752)
        y = inverse_left_mask(y,7,2636928640)
        y = inverse_right(y,11)
        return y
     
    def clone_mt(record):
        state = [recover(i) for i in record]
        gen = Random()
        gen.setstate((3,tuple(state+[0]),None))
        return gen

    f = open(r"预测.txt",'r').readlines()
    prng = []
    for i in f:
        prng.append(int(i.strip("\n")))

    g = clone_mt(prng[:624])
    for i in range(700):
        g.getrandbits(32)

    key = g.getrandbits(32)
    print(key)
    #True
这里用到了$random$库的几个函数:
    import random
    #print a random number:
    print(random.getrandbits(32))

    #capture the state:
    state = random.getstate()

    #print another random number:
    y=random.getrandbits(32)

    #restore the state:
    random.setstate(state)

    #and the next random number should be the same as when you captured the state:
    x=random.getrandbits(32)
    print(x==y)
所以只要能够还原$state$，就可以实现预测
      
3.逆向求到之前的随机数
既然可以预测，那么也能逆向，这个基于逆向$twist$部分。
    def backtrace(cur):
        high = 0x80000000
        low = 0x7fffffff
        mask = 0x9908b0df
        state = cur
        for i in range(623,-1,-1):
            tmp = state[i]^state[(i+397)%624]
            # recover Y,tmp = Y
            if tmp & high == high:
                tmp ^= mask
                tmp <<= 1
                tmp |= 1
            else:
                tmp <<=1
            # recover highest bit
            res = tmp&high
            # recover other 31 bits,when i =0,it just use the method again it so beautiful!!!!
            tmp = state[i-1]^state[(i+396)%624]
            # recover Y,tmp = Y
            if tmp & high == high:
                tmp ^= mask
                tmp <<= 1
                tmp |= 1
            else:
                tmp <<=1
            res |= (tmp)&low
            state[i] = res    
        return state
最终完整代码:
    from random import Random
    # right shift inverse
    def inverse_right(res,shift):
        tmp = res
        bits=len(bin(res)[2:])
        for i in range(bits//shift):
            tmp = res ^ tmp >> shift
        return tmp
    # right shift with mask inverse
    def inverse_right_values(res,shift,mask):
        tmp = res
        bits=len(bin(res)[2:])
        for i in range(bits//shift):
            tmp = res ^ tmp>>shift & mask
        return tmp
    # left shift inverse
    def inverse_left(res,shift):
        tmp = res
        bits=len(bin(res)[2:])
        for i in range(bits//shift):
            tmp = res ^ tmp << shift
        return tmp
    # left shift with mask inverse
    def inverse_left_values(res,shift,mask):
        tmp = res
        bits=len(bin(res)[2:])
        for i in range(bits//shift):
            tmp = res ^ tmp << shift & mask
        return tmp


    def backtrace(cur):
        high = 0x80000000
        low = 0x7fffffff
        mask = 0x9908b0df
        state = cur
        for i in range(3,-1,-1):
            tmp = state[i+624]^state[i+397]
            # recover Y,tmp = Y
            if tmp & high == high:
                tmp ^= mask
                tmp <<= 1
                tmp |= 1
            else:
                tmp <<=1
            # recover highest bit
            res = tmp&high
            # recover other 31 bits,when i =0,it just use the method again it so beautiful!!!!
            tmp = state[i-1+624]^state[i+396]
            # recover Y,tmp = Y
            if tmp & high == high:
                tmp ^= mask
                tmp <<= 1
                tmp |= 1
            else:
                tmp <<=1
            res |= (tmp)&low
            state[i] = res
        return state

    def recover_state(out):
        state = []
        for i in out:
            i = inverse_right(i,18)
            i = inverse_left_values(i,15,4022730752)
            i = inverse_left_values(i,7,2636928640)
            i = inverse_right(i,11)
            state.append(i)
        return state

    f = open(r"还原.txt","r").readlines()
    c = []
    for i in range(624):
        c.append(int(f[i].strip()))

    partS = recover_state(c)
    state = backtrace([0]*4+partS)[:624]
    print(state)

    prng = Random()
    prng.setstate((3,tuple(state+[0]),None))
    for i in range(4):
        print(prng.getrandbits(32))
    #True
4.逆向$__init__$函数
锁定关键代码$(1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)& 0xFFFFFFFF
显然$self.mt[i - 1] ^ self.mt[i - 1] >> 30)$这个可逆的，如1中逆向$extract\_number$
$& 0xFFFFFFFF$相当于取低$32$位，也就是模$2^32$，而$gcd(1812433253 ,2^32)=1$,那么模逆存在。
    from gmpy2 import invert

    def _int32(x):
        return int(0xFFFFFFFF & x)

    def init(seed):
        mt = [0] * 624
        mt[0] = seed
        for i in range(1, 624):
            mt[i] = _int32(1812433253 * (mt[i - 1] ^ mt[i - 1] >> 30) + i)
        return mt

    seed = 2080788869

    def invert_right(res,shift):
        tmp = res
        bits=len(bin(res)[2:])
        for i in range(bits//shift):
            res = tmp^res>>shift
        return _int32(res)

    def recover(last):   
        n = 1<<32
        inv = invert(1812433253,n)
        for i in range(623,0,-1):
            last = ((last-i)*inv)%n
            last = invert_right(last,30)
        return last

    state = init(seed)

    print(recover(state[-1]) == seed)
由此完成成对梅森算法的逆向,实现对随机数的预测和逆向。
继续记录废物striving的刷题日常，记录及心得，一些有趣的练习题和比赛题。
1.虎符杯cubic：
$\require{enclose}\enclose{horizontalstrike}{好家伙，就是做一道数学题呗，看一眼觉得还挺简单，结果还是跑去日论文}$
题目:求$(a,b,c)$满足$\frac{a}{b+c}+\frac{b}{a+c}+\frac{c}{a+b}=6$的$6$组正整数解，且三者两两互素。
整理一下主要思路就是：等式两边同时乘以$(a+b)(b+c)(a+c)$
有:$a^3+b^3+c^3-5(a^2b+ab^2+a^2c+ac^2+b^2c+bc^2)-9abc=0$
可以通过一个变换$x=f(a,b,c),y=g(a,b,c)$
得到椭圆曲线:$y^3=x^3+Ax^2+Bx$
在椭圆曲线上得到一个点$(x,y)$得到$a=\nu(x,y),b=\mu(x,y),c=\lambda(x,y)$
只要得到该线性变换$f,g$那么就可以实现该过程。
在论文中找到：对于$\frac{x}{y+z}+\frac{y}{x+z}+\frac{z}{x+y}=N$
可以通过:$x=\frac{-4(a+b+2c)(N+3)}{(2a+2b-c)+(a+b)N},y=\frac{4(a-b)(N+3)(2N+5)}{(2a+2b-c)+(a+b)N}$
化成椭圆曲线:$y^2=x^3+(4N^2+12N-3)x^2+32(N+3)x$
那么对应的$a=\frac{8(N+3)-x+y}{2(4-x)(N+3)},b=\frac{8(N+3)-x-y}{2(4-x)(N+3)},c=\frac{-4(N+3)-(N+2)x}{(4-x)(N+3)}$
可以在椭圆曲线上寻找到一个点，然后从他的倍点里面筛选符合条件的。
$\frac{ta}{tb+tc}=\frac{ta}{t(b+c)}=\frac{a}{b+c}$,那么就算得到的是分数形式，也可以通过通分，再约分求到$a,b,c$
    N=6
    a2=4*N^2+12*N-3
    a4=32*(N+3)

    E=EllipticCurve([0,a2,0,a4,0])
    #print(E.gens())
    x0,y0=-200,680
    P=E(x0,y0)
    l=[]
    ll=[]

    for i in range(1,200):
            p=(P*i).xy()
            l.append(p)

    for x,y in l:
            a=(8*(n+3)-x+y)/(2*(4-x)*(n+3))
            b=(8*(n+3)-x-y)/(2*(4-x)*(n+3))
            c=(-4*(n+3)-(n+2)*x)/((4-x)*(n+3))
            
            if a<=0 or b<=0 or c<=0:
                    continue
                
            abc=a.denominator()*b.denominator()*c.denominator()
            
            a=a*abc
            b=b*abc
            c=c*abc
            g=gcd(a,gcd(b,c))
            ll.append((a//g,b//g,c//g))

    ll=ll[:6]
    from pwn import *
    i=0
    while i<6:
        for xyz in ll:
            p.recvuntil("[>] x: ")
            p.sendline(str(xyz[0]))
            p.recvuntil("[>] y: ")
            p.sendline(str(xyz[1]))
            p.recvuntil("[>] z: ")
            p.sendline(str(xyz[2]))
            i+=1
    p.recvuntil("flag")

    #flag{1f88de74-b6af-4b2b-abd5-46356151698b} 
参考文章：       
[https://ami.uni-eszterhazy.hu/uploads/papers/finalpdf/AMI_43_from29to41.pdf][1]
[https://mlzeng.com/an-interesting-equation.html#sec-3][2]
[https://www.quora.com/How-do-you-find-the-positive-integer-solutions][3]

2.[羊城杯 2020]RRRRRRRSA
![2021-04-03T12:59:43.png][4]
首先回顾一下$winner$攻击,基于连分数的攻击方法。
首先连分数：$$x=a_0 + \frac {1}{a_1 + \frac {1}{a_2 + \frac {1}{a_3 + \frac {1}{a_4 + ...}}}}$$
$Legendre’s theorem$定理指出:若满足$|\alpha-\frac{c}{d}\lt \frac{1}{2d^2}|$，则称$\frac{c}{d}$是$\alpha$的连分数收敛。
证明:首先有:$ed-1=k\phi(n)$
两边同时除以$d\phi(n)$:$\frac{e}{\phi{n}}-\frac{k}{d}=\frac{1}{d\phi(n)}$
有:$\phi(n) \approx n,\frac{1}{d\phi(n)}\rightarrow 0$
那么就有:$\frac{e}{n}$略大于$\frac{k}{d}$,对$\frac{e}{n}$连分数展开，可以覆盖$\frac{k}{d}$
适用于:$d\lt\frac{N^\frac{1}{4}}{3}$
    from gmpy2 import *

    def rational_to_contfrac(x,y):
        # Converts a rational x/y fraction into a list of partial quotients [a0, ..., an]
        a = x // y
        pquotients = [a]
        while a * y != x:
            x, y = y, x - a * y
            a = x // y
            pquotients.append(a)
        return pquotients

    def convergents_from_contfrac(frac):
        # computes the list of convergents using the list of partial quotients
        convs = [];
        for i in range(len(frac)): convs.append(contfrac_to_rational(frac[0 : i]))
        return convs

    def contfrac_to_rational (frac):
        # Converts a finite continued fraction [a0, ..., an] to an x/y rational.
        if len(frac) == 0: return (0,1)
        num = frac[-1]
        denom = 1
        for _ in range(-2, -len(frac) - 1, -1): num, denom = frac[_] * num + denom, num
        return (num, denom)

    n = 90581
    e = 17993


    def crack_rsa(e, n):
        frac = rational_to_contfrac(e, n)
        convergents = convergents_from_contfrac(frac)
        
        for (k, d) in convergents:
            if k != 0 and (e * d - 1) % k == 0:
                phi = (e * d - 1) // k
                s = n - phi + 1
                # check if x*x - s*x + n = 0 has integer roots
                D = s * s - 4 * n
                if D >= 0:
                    sq = isqrt(D)
                    if sq * sq == D and (s + sq) % 2 == 0: return d

    d = crack_rsa(e, n)
    print(d)
再回到这个题:
可以发现$p1和p2$,$q1和q2$都相差不大，因为根据素数分布：两个相邻素数之间一般不会超过1500；
那么$\frac{N_1}{N_2}=(\frac{p_1}{p_2})^2\frac{q_1}{q_2}$
有$\frac{N_1}{N_2}\lt\frac{q_1}{q_2}\lt{1}$,相差是比较小的，对$\frac{N_1}{N_2}$进行连分数展开，就能覆盖到$\frac{q_1}{q_2}$。
    from gmpy2 import *
    from Crypto.Util.number import *
    def rational_to_contfrac(x,y):
        # Converts a rational x/y fraction into a list of partial quotients [a0, ..., an]
        a = x // y
        pquotients = [a]
        while a * y != x:
            x, y = y, x - a * y
            a = x // y
            pquotients.append(a)
        return pquotients

    def convergents_from_contfrac(frac):
        # computes the list of convergents using the list of partial quotients
        convs = [];
        for i in range(len(frac)): convs.append(contfrac_to_rational(frac[0 : i]))
        return convs

    def contfrac_to_rational (frac):
        # Converts a finite continued fraction [a0, ..., an] to an x/y rational.
        if len(frac) == 0: return (0,1)
        num = frac[-1]
        denom = 1
        for _ in range(-2, -len(frac) - 1, -1): num, denom = frac[_] * num + denom, num
        return (num, denom)

    N1=60143104944034567859993561862949071559877219267755259679749062284763163484947626697494729046430386559610613113754453726683312513915610558734802079868190554644983911078936369464590301246394586190666760362763580192139772729890492729488892169933099057105842090125200369295070365451134781912223048179092058016446222199742919885472867511334714233086339832790286482634562102936600597781342756061479024744312357407750731307860842457299116947352106025529309727703385914891200109853084742321655388368371397596144557614128458065859276522963419738435137978069417053712567764148183279165963454266011754149684758060746773409666706463583389316772088889398359242197165140562147489286818190852679930372669254697353483887004105934649944725189954685412228899457155711301864163839538810653626724347
    N2=60143104944034567859993561862949071559877219267755259679749062284763163484947626697494729046430386559610613113754453726683312513915610558734802079868195633647431732875392121458684331843306730889424418620069322578265236351407591029338519809538995249896905137642342435659572917714183543305243715664380787797562011006398730320980994747939791561885622949912698246701769321430325902912003041678774440704056597862093530981040696872522868921139041247362592257285423948870944137019745161211585845927019259709501237550818918272189606436413992759328318871765171844153527424347985462767028135376552302463861324408178183842139330244906606776359050482977256728910278687996106152971028878653123533559760167711270265171441623056873903669918694259043580017081671349232051870716493557434517579121

    def attack(N1,N2):
        frac = rational_to_contfrac(N1,N2)
        convergents = convergents_from_contfrac(frac)

        for (q1,q2) in convergents:
            if q1*q2!=0 and q1!=0 and q2!=1:
                if N1%q1==0 and N2%q2==0:
                    return q1,q2
                    break
    q1,q2=attack(N1,N2)
    p1=iroot(N1//q1,2)[0]
    p2=iroot(N2//q2,2)[0]
    phi1=p1*(p1-1)*(q1-1)
    phi2=p2*(p2-1)*(q2-1)
    e1=125932919717342481428108392434488550259190856475011752106073050593074410065655587870702051419898088541590032209854048032649625269856337901048406066968337289491951404384300466543616578679539808215698754491076340386697518948419895268049696498272031094236309803803729823608854215226233796069683774155739820423103
    e2=125932919717342481428108392434488550259190856475011752106073050593074410065655587870702051419898088541590032209854048032649625269856337901048406066968337289491951404384300466543616578679539808215698754491076340386697518948419895268049696498272031094236309803803729823608854215226233796069683774155739820425393
    d1=invert(e1,phi1)
    d2=invert(e2,phi2)
    c1=55094296873556883585060020895253176070835143350249581136609315815308788255684072804968957510292559743192424646169207794748893753882418256401223641287546922358162629295622258913168323493447075410872354874300793298956869374606043622559405978242734950156459436487837698668489891733875650048466360950142617732135781244969524095348835624828008115829566644654403962285001724209210887446203934276651265377137788183939798543755386888532680013170540716736656670269251318800501517579803401154996881233025210176293554542024052540093890387437964747460765498713092018160196637928204190194154199389276666685436565665236397481709703644555328705818892269499380797044554054118656321389474821224725533693520856047736578402581854165941599254178019515615183102894716647680969742744705218868455450832
    c2=39328446140156257571484184713861319722905864197556720730852773059147902283123252767651430278357950872626778348596897711320942449693270603776870301102881405303651558719085454281142395652056217241751656631812580544180434349840236919765433122389116860827593711593732385562328255759509355298662361508611531972386995239908513273236239858854586845849686865360780290350287139092143587037396801704351692736985955152935601987758859759421886670907735120137698039900161327397951758852875291442188850946273771733011504922325622240838288097946309825051094566685479503461938502373520983684296658971700922069426788236476575236189040102848418547634290214175167767431475003216056701094275899211419979340802711684989710130215926526387138538819531199810841475218142606691152928236362534181622201347
    m1=long_to_bytes(pow(c1,d1,N1))
    m2=long_to_bytes(pow(c2,d2,N2))
    print(m1+m2)
    #GWHT{3aadab41754799f978669d53e64a3aca}
前面连分数展开都是一样的。。。

3.[羊城杯 2020]Simple
题就不贴了，首先$winner$攻击分解$n$,前面提到$winner$攻击覆盖$\frac{k}{d}$,也就是可以求到欧拉函数$\phi(n)$，那么就可以分解$n$。
然后是$extend\:winner\:attack$，对于两个大$e$和相同的一个$n$,可以利用构造格利用$LLL$求解，具体原理:对于$e_i$有
$e_id_i=k(p-1)(q-1)+1$,令$s=1-p-q$,那么$e_id_i-k_iN=1+k_is--(W_i)$
$$
\left \{ 
\begin{array}{c}
e_1d_1-k_1\phi(n)=1\\
e_2d_2-k_2\phi(n)=1\\
\end{array}
\right.
$$
约掉$\phi(n)$有$e_1d_1k_2-e_2d_2k_1=k_2-k_1--(V)$
假设$d_i<N^{\alpha}$
联立四个等式:
$$
\left \{ 
\begin{array}{c}
k_1k_2\:\:\:=\:k_1k_2\\
e_1d_1k_2-k_1Nk_2\:\:=k_2+k_1sk_2---(W_1k_2)\\
e_2d_2k_1-e_1d_1k_2=k_1-k_2---(V)\\
d_1d_2e_1e_2-d_1 k_2 e_1 N-d_2 k_1 N+k_1 k_2 N^{2} = (1+k_1s_1)(1+k_2s_2)--(W_1W_2)\\
\end{array}
\right.
$$
由此可以构造：$A=(k_1k_2,d_1k_2,d_2k_1,d_1d_2)$ $L=\begin{pmatrix} 1&{-N}&0&N^2\\0&e_1&{-e_1}&{-e_1N}\\0&0&e_2&{-e_2N}\\0&0&0&e_1e_2\end{pmatrix}$  $B=(k_1k_2,k_2+k_1sk_2,k_1-k_2,(1+k_1s)(1+k_2s))$满足$AL=B$
其中我们可以进行一个估算:
$$
\left \{ 
\begin{array}{c}
e_1 \approx N\\
d \approx N^{\alpha}\\
k \approx d \approx N^{\alpha}\\
s=1-p-q \approx N^{0.5} \\
\end{array}
\right.
$$
所以$det(L)\approx N$,根据$Minkowoski's\:first\:theorem$,只有满足$\lambda_1(L) \le \sqrt n {det(L)}^{\frac{1}{n}}$时才能算是最短向量。$\lambda_1$ 代表在格$L$中最短的向量，其次为 $\lambda_2..$ , $n$为 $ L $的维数\)。
显然我们想要从$L$中格约出一个最短向量为$B$，那么还得对$L$的范数进行调整，可以通过对矩阵的列乘上一个倍数使其满足。
这里令$M_1=\sqrt N $,$M_2=N^{1+\alpha}$,第一列第二列第三列分别乘以$N,M_1,M_2$得到:
$L=\begin{pmatrix} N&{-M_1N}&0&N^2\\0&M_1e_1&{-e_1}&{-e_1N}\\0&0&e_2&{-M_2e_2N}\\0&0&0&e_1e_2\end{pmatrix}$ $B=(k_1k_2N,(k_2+k_1sk_2)M_1,(k_1-k_2)M_2,(1+k_1s)(1+k_2s))$
此时$\sqrt n {det(L)}^{\frac{1}{n}} \approx 2N^{\frac{\frac{13}{2}+\alpha}{4}}$ $\begin{Vmatrix} B \end{Vmatrix} \approx 2N^{1+2\alpha}$
那么 $2N^{1+2\alpha}\le  2N^{\frac{\frac{13}{2}+\alpha}{4}}$所以  $\alpha \le \frac{5}{14}$
然后利用$LLL$算法，求出$L$中的最短向量$B$,然后乘上$L$的逆求$A$，再求$\phi$。
    e1=114552459553730357961013268333698879659007919035942930313432809776799669181481660306531243618160127922304264986001501784564575128319884991774542682853466808329973362019677284072646678280051091964555611220961719302320547405880386113519147076299481594997799884384012548506240748042365643212774215730304047871679706035596550898944580314923260982768858133395187777029914150064371998328788068888440803565964567662563652062845388379897799506439389461619422933318625765603423604615137217375612091221578339493263160670355032898186792479034771118678394464854413824347305505135625135428816394053078365603937337271798774138959
    e2=27188825731727584656624712988703151030126350536157477591935558508817722580343689565924329442151239649607993377452763119541243174650065563589438911911135278704499670302489754540301886312489410648471922645773506837251600244109619850141762795901696503387880058658061490595034281884089265487336373011424883404499124002441860870291233875045675212355287622948427109362925199018383535259913549859747158348931847041907910313465531703810313472674435425886505383646969400166213185676876969805238803587967334447878968225219769481841748776108219650785975942208190380614555719233460250841332020054797811415069533137170950762289
    N=14922959775784066499316528935316325825140011208871830627653191549546959775167708525042423039865322548420928571524120743831693550123563493981797950912895893476200447083386549353336086899064921878582074346791320104106139965010480614879592357793053342577850761108944086318475849882440272688246818022209356852924215237481460229377544297224983887026669222885987323082324044645883070916243439521809702674295469253723616677245762242494478587807402688474176102093482019417118703747411862420536240611089529331148684440513934609412884941091651594861530606086982174862461739604705354416587503836130151492937714365614194583664241
    a=0.357
    M1=int(N^0.5)
    M2=int(N^(a+1))
    L=matrix([[N,-M1*N,0,N^2],
             [0,M1*e1,-M2*e1,-e1*N],
             [0,0,M2*e2,-e2*N],
             [0,0,0,e1*e2]])
    B=L.LLL()[0]
    A=B*L^-1
    phi=int(A[1]//A[0]*e1)
    import gmpy2
    from Crypto.Util.number import *
    d=gmpy2.invert(65537,phi)
    c=6472367338832635906896423990323542537663849304314171581554107495210830026660211696089062916158894195561723047864604633460433867838687338370676287160274165915800235253640690510046066541445140501917731026596427080558567366267665887665459901724487706983166070740324307268574128474775026837827907818762764766069631267853742422247229582756256253175941899099898884656334598790711379305490419932664114615010382094572854799421891622789614614720442708271653376485660139560819668239118588069312179293488684403404385715780406937817124588773689921642802703005341324008483201528345805611493251791950304129082313093168732415486813
    m=pow(c,d,N)
    print(long_to_bytes(m))
    #GWHT{3da44ca8379b98fdc1c86f9b34dcc1ef}


4.[羊城杯 2020]Power
![2021-04-03T17:09:56.png][5]
关键点主要在第一步求$p$吧，这里涉及到离散对数，即$y\equiv g^x\mod{p}$,求解$x$,可以发现$p-1$光滑，那么可以采用Pohlig-Hellman算法攻击，$\require{enclose}\enclose{horizontalstrike}{有关原理后面再写吧}$，sagemath内置了这个算法，然后解方程求$p$，最后可以得到$m\equiv c^{dp}\mod{p}$,推导:$dp\equiv\mod{p-1}$,那么：$m\equiv c^{d-k*(p-1)}\mod{p}$,由费马小定理可得:$m\equiv c^{dp}\mod{p}$当然当$m\lt p$的时候才成立。
    y=449703347709287328982446812318870158230369688625894307953604074502413258045265502496365998383562119915565080518077360839705004058211784369656486678307007348691991136610142919372779782779111507129101110674559235388392082113417306002050124215904803026894400155194275424834577942500150410440057660679460918645357376095613079720172148302097893734034788458122333816759162605888879531594217661921547293164281934920669935417080156833072528358511807757748554348615957977663784762124746554638152693469580761002437793837094101338408017407251986116589240523625340964025531357446706263871843489143068620501020284421781243879675292060268876353250854369189182926055204229002568224846436918153245720514450234433170717311083868591477186061896282790880850797471658321324127334704438430354844770131980049668516350774939625369909869906362174015628078258039638111064842324979997867746404806457329528690722757322373158670827203350590809390932986616805533168714686834174965211242863201076482127152571774960580915318022303418111346406295217571564155573765371519749325922145875128395909112254242027512400564855444101325427710643212690768272048881411988830011985059218048684311349415764441760364762942692722834850287985399559042457470942580456516395188637916303814055777357738894264037988945951468416861647204658893837753361851667573185920779272635885127149348845064478121843462789367112698673780005436144393573832498203659056909233757206537514290993810628872250841862059672570704733990716282248839
    c1=290707924192892686920253390955676600323331633814839708838347288502692494699485764473635783441705302268064111648851157070038783719749721994682837294625334517914882191486257362565066745587415388291939979195637720350919055988532145531805200483161599965215275808797976727969023747299578173497083532351976473770041800769265319548352841139802163279116490053292316399038329210043455932786945180855178341998049756983301499491011851026499269682821602212971062877270127451987836730083380463825717889123804613394241190839837791281657872259492589868751745327696030438893865069941066073554427558697972551085353027574529823439588670263047287131740802375738439636789806332323994866753085014446479034974063195632514803340511247735647970572837053148490258113394359072976858781060349776921428492973183958437965966963122069107876143476772436757554253049619918403996315720023020827394900507088006299225934263699192253079026440287311664705744424959801981503191480257138833694306501816837037995549817186335377411638035575004595417788588264823861850877111374085336446477943372458378834664678094751978400910288151519902977326995118727880223621964441498323865158898463327323193833062919619201107279964663654606753750042791368210261574897455830722232022689695292080269205470491791950839486861811469879413313773338916781857981641910031441448964144000585506870170898052132929034349451945051362244755750988705018897859238859476967568556992146975789444151432386692872801263000639711599152191790766776280
    g=2
    x=discrete_log(c1,mod(g,y))

    x=5535722692962580764045545539105119140941061679289569420988353884209653851308860058948669740693107863231179565602072744542122031789184119031739723962825082929025825322421201364211726001366490949760887367407718763255964735567971493859197583624076478457865073449246835949075135223468616834636386958924709024763349115622062848212445867198457630368236782421195503713107838541903829979118327675371550868768159024260793541264335548489228744367609071659968450303895118817379316060805148754136917043160175570565717388336822960389664337656603584425629662613786203920234401824957121860225422901340950436355650311392398098947210940

    var("p")
    eq1=2019*p^2 + 2020*p^3 + 2021*p^4==x
    solve([eq1],p)

    p=7234391427703598327916723159145232922047935397302241978344500497098972068808591685717500902909442183573763273395725479516998210374727754578133587007330339
    import gmpy2
    e=65537
    c=22524257534087703614496632403022329621384173069680778965750290698059674588465640878754707363673789674111671270645152584118206145007310499274423606886261969807360070526126452646719628307689968971699215841867636770320159256301550908771135042912287955209485328267670825390080110910391913063177323585204392804538642393453388536211144485389902591029350060800993352969569703901717308330574394200996651534321547814313195218895547718815009876393987398738932001924661338796059973950012706427109598830049455186171345179840564502215531573714428772608739268313985559628612004439028014417408631851880698512023740903181116906766066951473942201698375224240271523568161242951730224901227589413731025281719101368668617497947995579443908773425555177346524678673641140157885033923288401884
    dp=3272293505696712831419859641571956066667516012597886098021642320155056349966612629986261146617139998624603483170466852538289743936225789351270153550594329
    from Crypto.Util.number import *
    print(long_to_bytes(pow(c,dp,p)))
    #GWHT{f372e52f2a0918d92267ff78ff1a9f09}

5.[NPUCTF2020]babyLCG

 - 初始化$LCG$,其中模数，乘数，增量均已知，$seed$未知
 - 输出了前二十个，但是只知道高位
 - 再次利用$LCG$产生密钥和初始向量$iv$
很明显，如果我们能够恢复其中一个数，那么就可以完成解密。假设$LCG$递推关系为:$X_{n+1}=aX_n+b\mod{m}$,既然已知高位，那么将其划分为高位$(h_i)$和低位$(l_i)$。即可以得到：$h_{2}+l_{2}\equiv a(h_1+l_1)+b\mod m$就可以得到关于低位的一组递推关系。$l_{2}\equiv al_1+ah_1+b-h_{2}\mod m$也就是$l_{2}\equiv al_1+ah_1+b-h_{2}+mk_1$,可以造出一个三维的格子，令$A_1=a,B_1=ah_1+b-h_2$
就有：$(k_1,l_1,1) \begin{pmatrix}m&0&0\\A_1&1&0\\B_1&0&2^{64}\end{pmatrix}=(l_2,l_1,2^{64})$

对于$L=\begin{pmatrix}m&0&0\\A_1&1&0\\B_1&0&2^{64}\end{pmatrix} $,$B=(l_2,l_1,2^{64})$
显然满足$\begin{Vmatrix} B \end{Vmatrix} \le \sqrt n {det(L)}^{\frac{1}{n}}$，因此$LLL$能够格约出小向量$B$(但不一定是最小的)
然后还原$S_1$,求到$seed$,那么该$LCG$所有序列都已知了。
    a=107763262682494809191803026213015101802
    b=153582801876235638173762045261195852087
    m=226649634126248141841388712969771891297
    h1=7800489346663478448<<64
    h2=11267068470666042741<<64
    A=a
    B=a*h1+b-h2
    M=matrix([[m,0,0],
              [A1,1,0],
              [B1,0,2**64]])
    for i in M.LLL():
        if i[2]==2**64:
            L1=i[1]
    S1=h1+L1
    seed=(S1-b)*inverse_mod(a,m) %m
    print(seed)
    #73991202721494681711496408225724067994
显然这种方法应该是有局限性的，毕竟给了那么多组数据，只用了两组。参考[https://www.anquanke.com/post/id/204846][6]
还是同之前的推导，得到低位之间的递推关系：$l_{2}\equiv al_1+ah_1+b-h_{2}\mod{m}$
同理:$(h_3+l_3)\equiv a(h_2+l_2)+b \mod{m}$,代入$l_{2}\equiv al_1+ah_1+b-h_{2}\mod{m}$
得到$l_3\equiv aA_1l_1+aB_1+ah_2+b-h_3$设$A_2=aA_1$,$B_2=aB_1+ah_2+b-h_3$
也可以得到$l_3\equiv A_2l_2+B_2 \mod{m}$
显然$A_i=aA_{i_1},B_{i}=aB_{i-1}+ah_{i}+b-h{i+1}$
那么就可以求到所有$(A_1,A_2,...A_{19})$,$(B_1,B_2,...,B_{19})$
综上所述也就是$l_{i+1}=A_il_1+B_i+k_im$,那么根据$20$组数据，可以写成。
$\nu=(k_1,k_2,...,k_{19},l_1,1)$,$L=\begin{pmatrix}m&0&0&\cdots&0&0&0\\0&m&0&\cdots&0&0&0\\0&0&m&\cdots&0&0&0\\0&0&0&\ddots&0&0&0\\0&0&0&\cdots&m&0&0\\A_1&A_2&A_3&\cdots&A_{19}&1&0\\B_1&B_2&B_3&\cdots&B_{19}&0&2^{64}\end{pmatrix}$
$\omega=(l_2,l_3,...,l_20,l_1,2^{64})$ 满足$\nu L=\omega$
此时满足$\begin{Vmatrix} \omega \end{Vmatrix} \le \sqrt n {det(L)}^{\frac{1}{n}}$，所以格约$L$也可以得到小向量$\omega$，完成解密。

  [1]: https://ami.uni-eszterhazy.hu/uploads/papers/finalpdf/AMI_43_from29to41.pdf
  [2]: https://mlzeng.com/an-interesting-equation.html#sec-3
  [3]: https://www.quora.com/How-do-you-find-the-positive-integer-solutions-to-frac-x-y+z-+-frac-y-z+x-+-frac-z-x+y-4
  [4]: /usr/uploads/2021/04/2750502907.png
  [5]: /usr/uploads/2021/04/940717168.png
  [6]: https://www.anquanke.com/post/id/204846
  
  ## 紧接之前的文章，我们来了解一下NTRU，一种基于环的公钥系统 ##

> 系统建立在整系数多项式环上，设$R$表示为最高次数不超过$N-1$的所有整系数多项式集合。那么具体实现就可以通过模$x^{N}-1$,很容易理解，若产生$x^N$则可化为$1$，同理$X^{N+1}$化为$x$。

那么该环上的计算法则:设$$a=a+a_1*x+...+a_{N-1}*x^{N-1}$$ $$b=b_0+b_1*x+...+b_{N-1}*x^{N-1}$$ $$a+b=(a_0+b_0)+(a_1+b_1)x+...+(a_{N-1}+b_{N-1})x^{N-1}$$ $$a*b=c_0+c_1x+...+x_{N-1}x^{N-1}$$ $$c_k=a_0b_k+a_1b_{k-1}+...+a_{N-1}b_{k+1}=\sum\limits_{i+k\equiv k\mod{N}} a_ib_j$$
那么进入正题
 

 - 参数选择：
参数包括三个整数$(N,p,q)$和四个次数为$N-1$的整系数多项式集合$L_f,L_g,L_{\phi},L_m$,其中必须满足$gcd(p,q)=1$且$q\gt p$
 

 - 密钥的产生：
随机选择两个多项式$f,g\in L_g$,其中多项式$f$在模$q$和模$p$下均可逆，其逆元为$F_q$,$F_p$，即$F_q*f\equiv 1\mod{q}$ $F_p*f\equiv 1\mod{p}$,计算$h \equiv F_p*g \mod{q}$,$h$为公钥，$f$为私钥。

 - 加密：
将消息$m\in L_m$，进行如下加密:随机选取多项式$\phi \in L_{\phi}$,用公钥加密$$e\equiv p\phi *h+m \mod{q}$$

 - 解密:
$(1)$计算$a\equiv f*e\mod{q}$,$a$的系数在$\frac{-q}{2}\sim \frac{q}{2}$之间。
$(2)$计算$F_p*a\mod{p}$即可恢复明文$m$。
原理如下：
$$
\begin{equation}\begin{split} 
a&\equiv f*e\equiv f*p\phi*h+f*m\mod{q} \\ 
&\equiv f*p\phi*F_q*g+f*m\mod{q}\\
&\equiv p\phi*g+f*m\mod{q}\\
&\equiv p\phi*g+f*m\\
\end{split}\end{equation}
$$
正式因为$a$的参数选择合适，保证多项式$p\phi*g+f*m$的系数在$\frac{-q}{2}\sim \frac{q}{2}$之间
所以$p\phi*g+f*m$模$q$后结果不变,最终得到$$F_p*a \equiv F_p*p\phi*g+F_p*f*m\equiv m\mod{p}$$

理论上已经结束了，可是多项式不好操作呀，参考[https://latticehacks.cr.yp.to/ntru.html][1]
也就是$sagemath$的一些使用：
创建一个$Zx$类的对象，即整系数多项式，可进行多项式计算：
![2021-04-09T08:38:13.png][2]
循环卷积，也就是前面提到的模$x^n-1$,$NTRU$体系中就是采用的这种乘法
![2021-04-09T08:45:51.png][3]
$sgaemath$也可以采用$R = Zx.quotient(x^n-1)$,来创建一个加减乘除都是模$x^n-1$的类。
在解密时需要将系数控制到$\frac{-q}{2}\sim \frac{q}{2}$之间。
![2021-04-09T08:55:02.png][4]
产生$d$个系数为全为$-1$或$1$的$n$次多项式。
    from random import *
    Zx.<x>=ZZ[]
    def randomdpoly(d,n):
            assert d <= n
            result = n*[0]
            for j in range(d):
                    while True:
                            r = randrange(n)
                            if not result[r]: break
                    result[r] = 1 - 2*randrange(2)
            return Zx(result)
    print(randomdpoly(5,7))
    #x^5 - x^4 + x^3 + x + 1

模素数的除法:计算一个多项式在$\mod{x^n-1}\mod{q}$下的逆元。
    Zx.<x>=ZZ[]
    n=
    f=
    def invertmodprime(f,p):
            T = Zx.change_ring(Integers(p)).quotient(x^n-1)
            return Zx(lift(1 / T(f)))
            #litf(), 把一个在环R/I中的数, 转成在R中
模$2^n$的除法:
    #模2^n的除法，输入的q为2，4，8。。。
    def invertmodpowerof2(f,q):
         assert q.is_power_of(2)
         g = invertmodprime(f,2)
         while True:
           r = balancedmod(convolution(g,f),q)
           if r == 1: return g
           g = balancedmod(convolution(g,2 - r),q)
结合以上的代码可以得到$NTRU$的加密解密代码:
    #产生公钥私钥
    def keypair():
            while True:
                    try:
                            f = randomdpoly()
                            f3 = invertmodprime(f,3)
                            fq = invertmodpowerof(f,q)
                            break
                    except:
                            pass
            g = randomdpoly()
            publickey = balancedmod(3 * convolution(fq,g),q)
            secretkey = f,f3
            return publickey,secretkey
        
    #待加密明文
    def randommessage():
            result = list(randrange(3) - 1 for j in range(n))
            return Zx(result)
        
    #加密
    def encrypt(message,publickey):
         r = randomdpoly()
         return balancedmod(convolution(publickey,r) + message,q)
        
    #解密
    def decrypt(ciphertext,secretkey):
         f,f3 = secretkey
         a = balancedmod(convolution(ciphertext,f),q)
         return balancedmod(convolution(a,f3),3)

- 对系统的攻击，同背包密码体系，一样可以采用穷举或者中间相遇，那么尝试次数是很多的，不太可取。

- 引入格的思想，转化为格上的SVP问题：
若Eve能够找到$F_p$和$a$也就是找到$f,g$那么就可以完成解密。通过验证可以发现:$f*h\equiv g \mod{x^{N-1}} \in R_q$。也就是说我们可以写成$f*h=g+qu$,其中$u$是一个多项式。此时可以构造一个二维矩阵：
$(f,-u) \begin{pmatrix}1&h\\ 0&q\\ \end{pmatrix} =(f,g)$，$LLL$格约出来前半部分为私钥$f$。
当然这是多项式形式的，需要将系数提取出来形成一个$2n$维的格子。
就可以得到：
$$
\begin{pmatrix}
1&0&\cdots&0&h_0&h_1&\cdots&h_{n-1}\\
0&1&\cdots&0&h_{n-1}&h_0&\cdots&h_{n-2}\\
\vdots&\vdots&\vdots&\ddots&\vdots&\vdots&\vdots&\vdots\\
0&0&\cdots&1&h_1&h_{2}&\cdots&h_0\\
0&0&\cdots&0&q&0&\cdots&0\\
0&0&\cdots&0&0&q&\cdots&0\\
\vdots&\vdots&\vdots&\ddots&\vdots&\vdots&\vdots&\vdots\\
0&0&\cdots&0&0&0&\cdots&q\\
\end{pmatrix}
$$
也可以造成：$(-u,f) \begin{pmatrix}q&0\\ h&1\\ \end{pmatrix} =(g,f)$,那么$LLL$格约出来后半部分为私钥$f$。
$$
\begin{pmatrix}
q&0&\cdots&0&0&0&\cdots&0\\
0&q&\cdots&0&0&0&\cdots&0\\
\vdots&\vdots&\vdots&\ddots&\vdots&\vdots&\vdots&\vdots\\
0&0&\cdots&q&0&0&\cdots&0\\
h_0&h_1&\cdots&h_{n-1}&1&0&\cdots&0\\
h_{n-1}&h_0&\cdots&h_{n-2}&0&1&\cdots&0\\
\vdots&\vdots&\vdots&\ddots&\vdots&\vdots&\vdots&\vdots\\
h_1&h_{2}&\cdots&h_0&0&0&\cdots&1\\
\end{pmatrix}
$$
以$DASCTF$三月赛为例:
    def check(List):
        flag=True
        for i in List:
            if abs(i)>1:
                flag=False
                break
        return flag

    def balancedmod(f,N,q):
        g = list(((f[i] + q//2) %q) - q//2 for i in range(N))
        return Zx(g)

    def convolution(f,g,N):
        return (f*g) % (x^N-1)

    def invertmodprime(f,N,p):
        T = Zx.change_ring(Integers(p)).quotient(x^N-1)
        return Zx(lift(1 / T(f)))

    def decrypt(ciphertext,secretkey,N,q,p):
        f,fp = secretkey
        a = balancedmod(convolution(ciphertext,f,N),N,q)
        return balancedmod(convolution(a,fp,N),N,p)

    Zx.<x>=ZZ[]
    hx=14443*x^52 + 10616*x^51 + 11177*x^50 + 24769*x^49 + 23510*x^48 + 23059*x^47 + 21848*x^46 + 24145*x^45 + 12420*x^44 + 1976*x^43 + 16947*x^42 + 7373*x^41 + 16708*x^40 + 18435*x^39 + 18561*x^38 + 21557*x^37 + 16115*x^36 + 7873*x^35 + 20005*x^34 + 11543*x^33 + 9488*x^32 + 2865*x^31 + 11797*x^30 + 2961*x^29 + 14944*x^28 + 22631*x^27 + 24061*x^26 + 9792*x^25 + 6791*x^24 + 10423*x^23 + 3534*x^22 + 26233*x^21 + 14223*x^20 + 15555*x^19 + 3381*x^18 + 23641*x^17 + 2697*x^16 + 11303*x^15 + 6030*x^14 + 7355*x^13 + 20693*x^12 + 1768*x^11 + 10059*x^10 + 27822*x^9 + 8150*x^8 + 5458*x^7 + 21270*x^6 + 22651*x^5 + 8381*x^4 + 2819*x^3 + 3987*x^2 + 8610*x + 6022

    flag=hx.list()

    M=matrix([[0 for _ in range(2*N)] for _ in range(2*N)])
    N = 53
    q = 28019
    p = 257
    for i in range(N):
        for j in range(N):
            M[i+N,j] = int(flag[j-i])
            if i == j:
                M[i,j] = q
                M[N+i,N+j] =  1

    ex=7367*x^52 + 24215*x^51 + 5438*x^50 + 7552*x^49 + 22666*x^48 + 21907*x^47 + 10572*x^46 + 19756*x^45 + 4083*x^44 + 22080*x^43 + 1757*x^42 + 5708*x^41 + 22838*x^40 + 4022*x^39 + 9239*x^38 + 1949*x^37 + 27073*x^36 + 8192*x^35 + 955*x^34 + 4373*x^33 + 17877*x^32 + 25592*x^31 + 13535*x^30 + 185*x^29 + 9471*x^28 + 9793*x^27 + 22637*x^26 + 3293*x^25 + 27047*x^24 + 21985*x^23 + 13584*x^22 + 6809*x^21 + 24770*x^20 + 16964*x^19 + 8866*x^18 + 22102*x^17 + 18006*x^16 + 3198*x^15 + 19024*x^14 + 2777*x^13 + 9252*x^12 + 9684*x^11 + 3604*x^10 + 7840*x^9 + 17573*x^8 + 11382*x^7 + 12726*x^6 + 6811*x^5 + 10104*x^4 + 7485*x^3 + 858*x^2 + 15100*x + 15860

    for i in M.LLL():
        if check(i):
            fx=Zx(list(i[N:]))
            flag=""
            try:
                fp = invertmodprime(fx,N,p)
                for j in decrypt(ex,(fx,fp),N,q,p).list():
                    flag+=chr(abs(j))
                if "DASCTF" in flag:
                    print(flag)
                    break
            except:
                pass
            #DASCTF{9bba98e8024da44a3250acbc06bebc7b}

  [1]: https://latticehacks.cr.yp.to/ntru.html
  [2]: /usr/uploads/2021/04/1929894919.png
  [3]: /usr/uploads/2021/04/141176895.png
  [4]: /usr/uploads/2021/04/32987491.png
