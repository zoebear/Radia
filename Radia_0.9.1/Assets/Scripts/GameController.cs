/*! 
@file GameController.cs
@author Zoe Hardisty. <www.zoehardistydesign.com>
		<https://github.com/zoebear/Radia/GameController.cs>
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

Main initialization of the graph and UI. 

*/
using UnityEngine;
using UnityEngine.UI;
using UnityEngine.EventSystems;
using UnityEngine.Events;
using System.Collections;
using System.IO;
using System.Threading;
using SimpleJSON;
using EpForceDirectedGraph.cs;

public class GameController : MonoBehaviour {

	// Prefabs
	public Function defaultPrefab;
	public Function systemPrefab;
	public Function heapPrefab;
	public Function filePrefab;
	public Function socketPrefab;
	public Function stringPrefab;
	public Function cryptoPrefab;
	public Function dangerPrefab;
	public markHalo markPrefab;
	public Link linkPrefab;

	// For force directed graph
	private Graph graph;
	private ForceDirected3D physics;
	private FDRenderer render;
	private Thread renderThread;
	public float stiffness = 10.0f;
	public float repulsion = 1.0f;
	public float damping   = 0.5f;
	public bool runFDG 	   = true;	

	// For tracking instantiated objects
	public Hashtable nodes;
	public Hashtable links;

	// GUI Elements
	private GUIText statusText;
	public Texture2D crosshair;

	// References
	public UIController ui;
	public SelectionController selection;
	public LookInputModule look;
	public GameObject legend;
	public GameObject mark;
	public GameObject mark_list;
	public GameObject quit_dialog;

	// UI State Control
	private bool suspendInput = false;
	private Function selectedFunction;

	// Method for loading the JSON data from the API controller
	private IEnumerator LoadLayout(){
		graph = new Graph();

		statusText.text = "Loading radia.json...";

		string rawJson = null;
		
		//var req = new WWW(apiUrl + "/functions");
		string path_prefix;
		if (SystemInfo.operatingSystem.StartsWith ("Win")) {
			path_prefix = "\\";
		} else {
			path_prefix = "/../../";
		}

		//local app path for finding the JSON files
		var req = new WWW ("file://" + Application.dataPath + path_prefix + "radia.json");
		yield return req;
		if (req.error != null) {
			statusText.text = "Error reading radia.json";
			return false;
		}
		rawJson = req.text;

		statusText.text = "Processing Data";

		var j = JSON.Parse(rawJson);
		j = j["functions"];

		for(int i = 0; i < j.Count; i++) {
			float x = 0.0f;
			float y = 0.0f;
			float z = 0.0f;

			int category = 0;
			if (j[i]["category"] != null) {
				category = int.Parse(j[i]["category"]);
			}

			// (danger << 6) + (string << 5) + (fileio << 4) + (crypto << 3) + (socket << 2) + (heap << 1) + system
			//  64              32              16              8                4              2             1
			Function nodeObject;
			float scale = 1.0f;
			if ((category & 64) == 64) {
				nodeObject = Instantiate(dangerPrefab, new Vector3(x, y, z), Quaternion.identity) as Function;
			}
			else if ((category & 8) == 8) {
				nodeObject = Instantiate(cryptoPrefab, new Vector3(x, y, z), Quaternion.identity) as Function;
			}
			else if ((category & 4) == 4) {
				nodeObject = Instantiate(socketPrefab, new Vector3(x, y, z), Quaternion.identity) as Function;
			}
			else if ((category & 32) == 32) {
				nodeObject = Instantiate(stringPrefab, new Vector3(x, y, z), Quaternion.identity) as Function;
			}
			else if ((category & 16) == 16) {
				nodeObject = Instantiate(filePrefab, new Vector3(x, y, z), Quaternion.identity) as Function;
				scale = 1.5f;
			}
			else if ((category & 1) == 1) {
				nodeObject = Instantiate(systemPrefab, new Vector3(x, y, z), Quaternion.identity) as Function;
			}
			else if ((category & 2) == 2) {
				nodeObject = Instantiate(heapPrefab, new Vector3(x, y, z), Quaternion.identity) as Function;
				scale = 2.0f;
			} else {
				nodeObject = Instantiate(defaultPrefab, new Vector3(x, y, z), Quaternion.identity) as Function;
			}

			nodeObject.funcname = j[i]["name"];
			nodeObject.address = ulong.Parse(j[i]["address"]);
			nodeObject.attributes = category;
			if (j[i]["size"] != null) {
				nodeObject.size = int.Parse(j[i]["size"]);
			} else {
				nodeObject.size = 0;
			}
			nodeObject.module_name   = j[i]["module_name"];
			nodeObject.functag		 = j[i]["tag"];
			nodeObject.comment		 = j[i]["comment"];
			nodeObject.longname		 = j[i]["long_name"];
			nodeObject.basic_blk_cnt = int.Parse(j[i]["basic_blk_cnt"]);

			if (j[i]["dangerous_list"] != null) {
				nodeObject.dangerous_calls = new string[j[i]["dangerous_list"].Count];
				for (int c = 0; c < j[i]["dangerous_list"].Count; c++) {
					nodeObject.dangerous_calls[c] = j[i]["dangerous_list"][c];
				}
			}

			if (j[i]["strings"] != null) {
				nodeObject.strings = new string[j[i]["strings"].Count];
				for (int c = 0; c < j[i]["strings"].Count; c++) {
					nodeObject.strings[c] = j[i]["strings"][c];
				}
			}

			nodeObject.transform.localScale += new Vector3(scale, scale, scale);
			nodes.Add(nodeObject.address, nodeObject);

			// For force directed graph
			NodeData data = new NodeData();
			data.label = nodeObject.address.ToString();
			data.mass = (float)nodeObject.size / 50.0f + 10.0f;
			graph.CreateNode(data);

			statusText.text = "Loading Functions: Function " + nodeObject.funcname;

			if(i % 100 == 0)
				yield return true;
		}

		j = JSON.Parse(rawJson);
		j = j["callgraph"];


		for(int i = 0; i < j.Count; i++) {
			ulong srcid = ulong.Parse(j[i]["source"]);
			ulong dstid = ulong.Parse(j[i]["target"]);

			if (FindDupLink (srcid, dstid)) {
				continue;
			}

			Link linkObject = Instantiate(linkPrefab, new Vector3(0, 0, 0), Quaternion.identity) as Link;
			linkObject.id       = i+1;
			linkObject.sourceId = srcid;
			linkObject.targetId = dstid;
			links.Add(linkObject.id, linkObject);

			// For force directed graph
			Node node1 = graph.GetNode(linkObject.sourceId.ToString());
			Node node2 = graph.GetNode(linkObject.targetId.ToString());
			EdgeData data = new EdgeData();
			data.label = linkObject.sourceId.ToString()+"-"+linkObject.targetId.ToString();
			data.length = 1.0f;
			graph.CreateEdge(node1, node2, data);

			statusText.text = "Loading Callgraph: Call " + linkObject.id.ToString();
			
			if(i % 100 == 0)
				yield return true;
		}

		// Map node edges
		MapLinkFunctions();

		// For force directed graph
		physics = new ForceDirected3D(graph, // instance of Graph
	                                  stiffness, // stiffness of the spring
	                                  repulsion, // node repulsion rate
	                                  damping    // damping rate 
	                                 );
		render = new FDRenderer(physics);
		render.setController(this);

		statusText.text = "";

		Camera.main.transform.LookAt (new Vector3 (0f, 0f, 0f));

		renderThread = new Thread(new ThreadStart(FDRenderThread));
		renderThread.Start ();
	}

	// Method for stripping out duplicate links -- too much overhead
	private bool FindDupLink(ulong srcid, ulong dstid) {
		foreach (int key in links.Keys) {
			Link link = links [key] as Link;
			if (srcid == link.sourceId && dstid == link.targetId) {
				return true;
			}
		}
		return false;
	}

	// Method for mapping links to nodes
	private void MapLinkFunctions(){
		foreach(int key in links.Keys){
			Link link = links[key] as Link;
			link.source = nodes[link.sourceId] as Function;
			link.target = nodes[link.targetId] as Function;
			if (link.source != null) {
				link.source.egress_calls += 1;
				link.source.egress_links.Add (link);
			}
			if (link.target != null) {
				link.target.ingress_calls += 1;
				link.target.ingress_links.Add(link);
			}
		}
	}

	void Start () {
		Cursor.visible = false;
		ui = GameObject.Find ("NodeUIOverlay").GetComponent<UIController> ();
		selection = GameObject.Find ("SelectionCanvas").GetComponent<SelectionController> ();
		look = GameObject.Find ("EventSystem").GetComponent<LookInputModule> ();
		legend = GameObject.Find ("LegendCanvas");
		mark = GameObject.Find ("MarkCanvas");
		mark_list = GameObject.Find ("MarklistCanvas");
		quit_dialog = GameObject.Find ("QuitDialogCanvas");
		//HideLegend ();

		ui.Startup ();
		quit_dialog.SetActive (false);
		ui.gameObject.SetActive (false);
		selection.gameObject.SetActive (false);
		mark.SetActive (false);
		mark_list.SetActive (false);

		nodes = new Hashtable();
		links = new Hashtable();

		statusText = GameObject.Find("StatusText").GetComponent<GUIText>();
		statusText.text = "";

		StartCoroutine( LoadLayout() );
		//GameObject.Find ("SelectionCanvas").SetActive (false);
	}

	// This thread is used to periodically recalc the force directed graph
	void FDRenderThread() {
		while(runFDG) {
			render.Draw (0.1f);
		}
	}

	// Draw the cross hair
	void OnGUI() {
		float xMin = (Screen.width / 2) - (crosshair.width / 2);
		float yMin = (Screen.height / 2) - (crosshair.height / 2);
		GUI.DrawTexture(new Rect(xMin, yMin, crosshair.width, crosshair.height), crosshair);
	}

	// Kill the threat used to render the FDG... this is ~99% reliable for some reason
	void OnApplicationQuit() {
		Cleanup ();
	}

	public void Cleanup() {
		runFDG = false;
		Thread.Sleep (500);
		if (renderThread != null && renderThread.IsAlive) {
			renderThread.Abort ();
		}
		Cursor.visible = true;
	}

	public void ToggleFDGCalc() {
		if (runFDG == true) {
			runFDG = false;
		} else {
			runFDG = true;
		}
	}

	public void SelectFunction(GameObject selected) {
		Debug.Log (selected);
		Function sel_func = selected.transform.root.GetComponent<Function> ();
		if (sel_func != null) {
			SetUIActive (true);
			SetSelectedFunction (sel_func);
		}
	}

	public bool InputActive() {
		return !(suspendInput);
	}

	public void SetInputActive(bool state) {
		suspendInput = !(state);
	}

	public void SetUIActive(bool state) {
		if (state) {
			ui.gameObject.SetActive (true);
			selection.gameObject.SetActive (true);
		} else {
			if (selectedFunction != null) {
				selectedFunction.resetState ();
			}
			selectedFunction = null;
			selection.SetFunction(null);
			ui.gameObject.SetActive(false);
			selection.gameObject.SetActive(false);
			mark.SetActive (false);
		}
	}

	public bool GetUIActive() {
		return ui.gameObject.activeSelf;
	}

	public void SetSelectedFunction(Function func) {
		if (selectedFunction != null) {
			selectedFunction.resetState ();
		}
		selectedFunction = func;
		ui.SetFunction (func);
		selection.SetFunction (func);
		selectedFunction.updateState ();
	}

	public Function GetSelectedFunction() {
		return selectedFunction;
	}

	public void EditComment() {
		SetInputActive (false);
		ui.SelectCommentInput ();
	}

	public void EditMark() {
		Debug.Log ("EditMark(): disabled key input");
		SetInputActive (false);
		ShowMark ();
		Debug.Log ("EditMark(): selecting input box");
		ui.SelectMarkInput ();
	}

	public void EditFunctionName() {
		SetInputActive (false);
		ui.SelectFunctionNameInput ();
	}

	public void HideLegend() {
		legend.SetActive (false);
	}

	public void ShowLegend() {
		legend.SetActive (true);
	}

	public void ToggleLegend() {
		if (legend.activeSelf) {
			HideLegend();
		} else {
			ShowLegend();
		}
	}

	public void ShowMark() {
		mark.SetActive (true);
		ui.SetMark ();
	}

	public void HideMark() {
		mark.SetActive (false);
	}

	public void ShowMarkList() {
		SetInputActive (false);
		mark_list.SetActive (true);
		ui.SetMarkList ();
		ui.SelectMarkList ();
	}

	public void HideMarkList() {
		MarkedController [] items = mark_list.GetComponentsInChildren<MarkedController> ();
		foreach (MarkedController item in items) {
			GameObject.Destroy(item.gameObject);
		}
		mark_list.SetActive (false);
		SetInputActive (true);
	}
}
