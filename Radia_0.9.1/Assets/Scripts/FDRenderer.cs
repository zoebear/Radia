/*! 
@file FDRenderer.cs
@author Zoe Hardisty. <www.zoehardistydesign.com>
		<https://github.com/zoebear/Radia/FDRenderer.cs>
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

Force Directed Graph Renderer

*/
using UnityEngine;
using System.Collections;
using EpForceDirectedGraph.cs;

public class FDRenderer : AbstractRenderer {
	private GameController controller;

	public FDRenderer(IForceDirected iForceDirected): base(iForceDirected)
	{
		// Your initialization to draw
	}
	
	public override void Clear()
	{
		// Clear previous drawing if needed
		// will be called when AbstractRenderer:Draw is called
	}
	
	protected override void drawEdge(Edge iEdge, AbstractVector iPosition1, AbstractVector iPosition2)
	{
		// Draw the given edge according to given positions
	}
	
	protected override void drawNode(Node iNode, AbstractVector iPosition)
	{
		// Draw the given node according to given position
		Function f = controller.nodes [ulong.Parse (iNode.Data.label)] as Function;
		f.nx = iPosition.x;
		f.ny = iPosition.y;
		f.nz = iPosition.z;
	}

	public void setController(GameController c) {
		controller = c;
	}
}