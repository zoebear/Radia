/*! 
@file MarkedController.cs
@author Zoe Hardisty. <www.zoehardistydesign.com>
		<https://github.com/zoebear/Radia/MarkedController.cs>
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

Allows the nodes to be graphically marked and added to the MarklistScrollview with notes.

*/
using UnityEngine;
using UnityEngine.UI;
using UnityEngine.EventSystems;
using UnityEngine.Events;
using System.Collections;
using System;

public class MarkedController : MonoBehaviour, ISelectHandler {
	public Function node;
	public bool selected = false;

	public Text label;
	public Text desc;
	public Image background;
	public Image marker;

	public void OnSelect(BaseEventData eventData)
	{
		GameObject.Find ("MarklistScrollview").GetComponent<ScrollRectFollow>().CenterToItem(this.GetComponent<RectTransform>());
		selected = true;
	}

	public void OnDeSelect(BaseEventData eventData)
	{
		selected = false;
	}

	public void Submit()
	{
		CameraControlZeroG ccontrol = GameObject.Find ("Main Camera").GetComponent<CameraControlZeroG>();
		ccontrol.SetFocus (node);
	}

	public void Init()
	{
		label = this.GetComponentsInChildren<Text> () [0];
		desc = this.GetComponentsInChildren<Text> () [1];
		background = this.GetComponent<Image> ();
		marker = this.GetComponentsInChildren<Image> () [1];
	}

	void Start() {

	}

	void Update() {
		if (node != null) {
			label.text = String.Format ("0x{0}", node.address.ToString ("X").PadLeft (8, '0')) + " " + node.funcname.ToString ();
			desc.text = node.mark.ToString ();
			if (selected) {
				background.color = new Color (100f, 100f, 100f, 120f);
			} else {
				background.color = new Color (62f, 62f, 62f, 120f);
			}
		}
	}
}
