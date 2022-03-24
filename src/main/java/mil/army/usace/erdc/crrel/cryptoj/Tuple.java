/*
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 
 */

package mil.army.usace.erdc.crrel.cryptoj;

/**
 *
 * @author k3endrsg
 */
public class Tuple <A, B> implements Comparable{

  private A a;
  private B b;

  public Tuple(A a, B b) {
    this.a = a;
    this.b = b;
  }

  public A getA() {
    return this.a;
  }

  public B getB() {
    return this.b;
  }

  @Override
  public int compareTo(Object o) {
    Tuple compareTuple=(Tuple)o;
    int aCompare= ((Comparable)this.a).compareTo(compareTuple.getA());
    if(aCompare==0){
        return ((Comparable)this.b).compareTo(compareTuple.getB());
    }
    else{
        return aCompare;
    }
  }
  
  

}
