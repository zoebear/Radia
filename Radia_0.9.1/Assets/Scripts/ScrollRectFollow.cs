/*! 
@file ScrollRectFollow.cs
@author Zoe Hardisty. <www.zoehardistydesign.com>
		<https://github.com/zoebear/Radia/ScrollRectFollow.cs>
@date June 2015
@version 0.9.1

@section LICENSE

The MIT License (MIT)

Copyright (c) 2015 Zoe Hardisty 

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


@section DESCRIPTION

Control for the marked list scroll area. 

*/
using UnityEngine;
using System.Collections;
using UnityEngine.UI;

public class ScrollRectFollow : MonoBehaviour {

	private ScrollRect scroll;
	private RectTransform scrollTransform;
	private RectTransform contentTransform;
	
	void Start()
	{
		scroll = GetComponent<ScrollRect>();
		scrollTransform = GetComponent<RectTransform>();
		contentTransform = GameObject.Find ("MarklistContent").GetComponent<RectTransform> ();
	}
	
	public void CenterToItem(RectTransform obj)
	{
		if (obj != null && contentTransform != null) {
			float relativePos = (contentTransform.rect.height - ((float)Mathf.Abs (obj.localPosition.y))) / contentTransform.rect.height;
			float offset = (relativePos - 0.5f) * -50f;
			float normalizePosition = (contentTransform.rect.height - ((float)Mathf.Abs (obj.localPosition.y) + offset)) / contentTransform.rect.height;
			scroll.verticalNormalizedPosition = normalizePosition;
		}
	}

}
