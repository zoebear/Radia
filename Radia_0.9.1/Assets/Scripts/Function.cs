/*! 
@file Functions.cs
@author Zoe Hardisty. <www.zoehardistydesign.com>
		<https://github.com/zoebear/Radia/Functions.cs>
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

Initialization, provisioning and assigning values and prefabs to the imported reverse engineering data. 

*/
using UnityEngine;
using UnityEngine.UI;
using System.Collections;
using System.Collections.Generic;

public class Function : MonoBehaviour {

	public ulong address;
	public string funcname;
	public string longname;
	public int attributes;
	public int size;
	public int basic_blk_cnt;
	public int ingress_calls = 0;
	public int egress_calls = 0;
	public string[] dangerous_calls;
	public string[] strings;
	public string module_name;
	public string functag;
	public string comment;
	public bool marked;
	public string mark;
	public List<Link> ingress_links = new List<Link>();
	public List<Link> egress_links = new List<Link>();

	public float nx = 0.0f;
	public float ny = 0.0f;
	public float nz = 0.0f;

	private float smoothTime = 10.0F;
	private Vector3 velocity = Vector3.zero;
	private Text nodeText;
	private Canvas nodeCanvas;
	private GameController controller;
	private markHalo halo;

	public void updateState() {
		foreach (Link link in egress_links) {
			link.setEgress ();
		}
		
		foreach (Link link in ingress_links) {
			link.setIngress ();
		}
	}

	public void resetState() {
		foreach (Link link in egress_links) {
			link.setDefault ();
		}
		
		foreach (Link link in ingress_links) {
			link.setDefault ();
		}
	}

	public void SetMarked(bool state) {
		if (state == true && !marked) {
			halo = Instantiate (controller.markPrefab, transform.localPosition, Quaternion.identity) as markHalo;
			marked = true;
		} else if (state == false && marked) {
			Destroy (halo.gameObject);
			marked = false;
		}
	}

	void Start() {
		nodeText = GetComponentsInChildren<Text> ()[0];
		nodeCanvas = GetComponentInChildren<Canvas> ();
		controller = GameObject.Find ("GameController").GetComponent<GameController> ();
	}

	void Update () {
		nodeCanvas.transform.rotation = Camera.main.transform.rotation;
		if (controller.selection.node == this) {
			nodeText.text = "";
		} else {
			nodeText.text = funcname;
		}
		Vector3 targetPosition = new Vector3(nx, ny, nz);
		transform.position = Vector3.SmoothDamp(transform.position, targetPosition, ref velocity, smoothTime);
		if (halo != null) {
			halo.transform.position = transform.position;
			halo.transform.rotation = Camera.main.transform.rotation;
		}
	}
}
