/*! 
@file Link.cs
@author Zoe Hardisty. <www.zoehardistydesign.com>
		<https://github.com/zoebear/Radia/Link.cs>
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

Creates the directional node linkages and assigns their look. 

*/
using UnityEngine;
using System.Collections;

public class Link : MonoBehaviour {

	public int id;
	public Function source;
	public Function target;
	public ulong sourceId;
	public ulong targetId;

	public bool loaded = false;

	private LineRenderer line;
	private Texture texture_default;
	private Texture texture_ingress;
	private Texture texture_egress;

	void Start () {
		line = gameObject.AddComponent<LineRenderer>();
		line.material = new Material (Shader.Find("Particles/Additive"));						
		texture_default = (Texture)Resources.Load ("directionalLines") as Texture;				// Main white arrows
		texture_ingress = (Texture)Resources.Load ("directionalLinesIngress") as Texture;		// Redish arrows
		texture_egress  = (Texture)Resources.Load ("directionalLinesEgress") as Texture;		// Minty arrows
		line.material.mainTexture = texture_default;
		line.material.mainTexture.wrapMode = TextureWrapMode.Repeat;
		line.SetWidth(0.3f, 0.3f);
		line.SetVertexCount(2);
		line.SetPosition(0, new Vector3(0,0,0));
		line.SetPosition(1, new Vector3(1,0,0));
	}

	void Update () {
		if (source && target) {
			Vector3 m = (target.transform.position - source.transform.position) + source.transform.position;
			line.SetPosition(0, source.transform.position);
			line.SetPosition(1, m);
			line.material.mainTextureScale = new Vector2((target.transform.position - source.transform.position).magnitude / 5.0f, 1.0f);
		}
	}

	public void setIngress() {
		line.material.mainTexture = texture_ingress;
	}

	public void setEgress() {
		line.material.mainTexture = texture_egress;
	}

	public void setDefault() {
		line.material.mainTexture = texture_default;
	}
}