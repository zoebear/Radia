/*! 
@file UIController.cs
@author Zoe Hardisty. <www.zoehardistydesign.com>
		<https://github.com/zoebear/Radia/UIController.cs>
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

Initiates the Node UI and populates the information about the specific node. 

*/
using UnityEngine;
using UnityEngine.UI;
using UnityEngine.EventSystems;
using UnityEngine.Events;
using System;
using System.Collections;

public class UIController : MonoBehaviour {
	private Text ingress_call_text;
	private Text egress_call_text;
	private Text dangerous_func_text;
	private Text dangerous_func_count_text;
	private Text basic_blks_text;
	private Text strings_text;
	private Text strings_count_text;
	private Text func_address_text;
	private Text module_name_text;
	private Text func_name_text;
	private InputField comment_input;
	private InputField func_name_input;
	private InputField mark_input;
	private HorizontalLayoutGroup func_name_group;
	private Canvas marked_scroll_canvas;

	private string str;
	private string danger;
	private string long_name;
	private string module_name;
	public Function node;
	private GameController controller;
	private int marked_index;

	public Sprite dangerous_sprite;
	public Sprite string_sprite;
	public Sprite socket_sprite;
	public Sprite file_sprite;
	public Sprite crypto_sprite;
	public Sprite system_sprite;
	public Sprite heap_sprite;
	public Sprite default_sprite;

	public MarkedController markedItemPrefab;

	public void SetFunction(Function func) {
		for (int i = 0; i < 40; i++) {	
			GameObject go = GameObject.Find ("UI Image " + i.ToString());
			if (go != null) {
				GameObject.Destroy(go);
			}
		}

		node = func;

		ingress_call_text.text 			= node.ingress_calls.ToString ();
		egress_call_text.text          	= node.egress_calls.ToString ();
		basic_blks_text.text 			= node.basic_blk_cnt.ToString ();
		dangerous_func_count_text.text 	= node.dangerous_calls.Length.ToString ();
		strings_count_text.text 		= node.strings.Length.ToString ();

		if (node.comment != null) {
			comment_input.text = node.comment.ToString ();
		} else {
			comment_input.text = "";
		}

		str = "";
		foreach (string s in node.strings) {
			str = str + s + "\n";
		}
		strings_text.text = str;
		
		danger = "";
		int index = 0;
		foreach (string f in node.dangerous_calls) {
			string [] funcinfo = f.Split('*');
			string funcname = funcinfo[1];
			string category = funcinfo[0];

			MakeDangerIcon(category, index);

			danger = danger + funcname + "\n";
			index++;
		}

		func_address_text.text = String.Format ("0x{0}", node.address.ToString("X").PadLeft(8, '0'));

		long_name = node.longname.ToString ();
		if (long_name.Length > 80) {
			long_name = long_name.Substring (0, 80);
		}

		float panel_width = Mathf.Clamp (252.0f + (float)(long_name.Length - 28) * 9.0f, 252.0f, 650.0f);
		float input_width = Mathf.Clamp (202.0f + (float)(long_name.Length - 28) * 9.0f, 202.0f, 600.0f);

		func_name_group.transform.GetComponent<RectTransform> ().SetSizeWithCurrentAnchors(RectTransform.Axis.Horizontal, panel_width);
		func_name_text.transform.GetComponent<RectTransform> ().SetSizeWithCurrentAnchors(RectTransform.Axis.Horizontal, input_width);

		func_name_input.text = long_name;
		dangerous_func_text.text = danger;

		module_name_text.text = node.module_name.ToString ();
	}

	private void MakeDangerIcon(string category, int index) {
		if (category == "dangerous") {
			CreateUISprite (dangerous_sprite, index);
		} else if (category == "string") {
			CreateUISprite (string_sprite, index);
		} else if (category == "crypto") {
			CreateUISprite (crypto_sprite, index);
		} else if (category == "file") {
			CreateUISprite (file_sprite, index);
		} else if (category == "socket") {
			CreateUISprite (socket_sprite, index);
		} else if (category == "heap") {
			CreateUISprite (heap_sprite, index);
		} else if (category == "system") {
			CreateUISprite (system_sprite, index);
		} else {
			CreateUISprite (default_sprite, index);
		}
	}

	private void CreateUISprite(Sprite sprite, int index) {
		GameObject go = new GameObject ("UI Image " + index.ToString ());
		Image image = go.AddComponent<Image> ();
		image.sprite = sprite;
		image.transform.localScale = new Vector2 (0.1f, 0.08f);
		image.transform.localPosition = new Vector2 (-92.5f, 86.2f + (float)(index * -19.5));
		go.transform.SetParent (GameObject.Find ("StringsMiddle").transform, false);
	}
	
	private void ChangeComment(string comment)
	{
		node.comment = comment;
		controller.SetInputActive (true);
	}

	public void SetMark() {
		if (node != null && node.mark != null) {
			mark_input.text = node.mark;
		}
	}

	public void SetMarkList() {
		marked_index = 0;
		int mi_index = 0;

		foreach (ulong key in controller.nodes.Keys) {
			Function node = controller.nodes [key] as Function;
			if (node.marked) {
				MarkedController mi = Instantiate(markedItemPrefab, new Vector3(0, 0, 0), Quaternion.identity) as MarkedController;
				mi.Init ();
				mi.gameObject.transform.SetParent(GameObject.Find ("MarklistContent").transform);
				mi.node = node;
				int category = node.attributes;
				if ((category & 64) == 64) {
					mi.marker.sprite = dangerous_sprite;
				}
				else if ((category & 8) == 8) {
					mi.marker.sprite = crypto_sprite;
				}
				else if ((category & 4) == 4) {
					mi.marker.sprite = socket_sprite;
				}
				else if ((category & 32) == 32) {
					mi.marker.sprite = string_sprite;
				}
				else if ((category & 16) == 16) {
					mi.marker.sprite = file_sprite;
				}
				else if ((category & 1) == 1) {
					mi.marker.sprite = system_sprite;
				}
				else if ((category & 2) == 2) {
					mi.marker.sprite = heap_sprite;
				} else {
					mi.marker.sprite = default_sprite;
				}
				mi.transform.localPosition = new Vector3(0, -25 + (-50 * mi_index), 0);
				mi.transform.localScale = new Vector3(1.0f, 1.0f);
				mi_index += 1;
			}
		}
		RectTransform rt = GameObject.Find ("MarklistContent").GetComponent<RectTransform>();
		rt.sizeDelta = new Vector2(373, mi_index * 50);

		GameObject.Find ("MarklistHdrCount").GetComponent<Text> ().text = mi_index.ToString ();
	}

	public void SelectMarkList() {
		Debug.Log ("SelectMarkList(): Triggering selection");
		GameObject mi = GameObject.Find ("MarkedItem");
		if (mi != null) {
			Button mlbutton = mi.GetComponent<Button> ();
			EventSystem.current.SetSelectedGameObject (mlbutton.gameObject, null);
			mlbutton.OnPointerClick (new PointerEventData (EventSystem.current));
		}
	}

	public void SelectNextMark() {
		Button [] items = GameObject.Find ("MarklistContent").GetComponentsInChildren<Button> ();
		if (marked_index < (items.Length - 1)) {
			marked_index += 1;
		}
		EventSystem.current.SetSelectedGameObject (items[marked_index].gameObject, null);
		items[marked_index].OnPointerClick (new PointerEventData (EventSystem.current));
	}

	public void SelectPreviousMark() {
		Button [] items = GameObject.Find ("MarklistContent").GetComponentsInChildren<Button> ();
		if (marked_index > 0) {
			marked_index -= 1;
		}
		EventSystem.current.SetSelectedGameObject (items[marked_index].gameObject, null);
		items[marked_index].OnPointerClick (new PointerEventData (EventSystem.current));
	}

	public void SelectMark() {
		Button [] items = GameObject.Find ("MarklistContent").GetComponentsInChildren<Button> ();
		if (marked_index > -1 && marked_index < items.Length) {
			items[marked_index].GetComponent<MarkedController>().Submit();
		}
	}

	private void ChangeMark (string text) {
		Debug.Log ("ChangeMark(): text = " + text);
		if (text != null && text.Length > 0) {
			node.SetMarked(true);
		} else {
			node.SetMarked(false);
		}
		node.mark = text;
		controller.HideMark ();
		controller.SetInputActive (true);
	}

	public void SelectCommentInput() {
		EventSystem.current.SetSelectedGameObject (comment_input.gameObject, null);
		comment_input.OnPointerClick (new PointerEventData (EventSystem.current));
	}

	public void SelectMarkInput() {
		EventSystem.current.SetSelectedGameObject (mark_input.gameObject, null);
		mark_input.OnPointerClick (new PointerEventData (EventSystem.current));
	}

	private void ChangeFunctionName(string funcname) {
		node.longname = funcname;
		node.funcname = funcname;
		controller.SetInputActive (true);
	}

	public void SelectFunctionNameInput() {
		EventSystem.current.SetSelectedGameObject (func_name_input.gameObject, null);
		func_name_input.OnPointerClick (new PointerEventData (EventSystem.current));
	}

	public void Startup() {
		controller = GameObject.Find ("GameController").GetComponent<GameController> ();
		ingress_call_text = GameObject.Find ("IngressNumber").GetComponent<Text> ();
		egress_call_text = GameObject.Find ("EgressNumber").GetComponent<Text> ();
		dangerous_func_text = GameObject.Find ("TheStrings").GetComponent<Text> ();
		dangerous_func_count_text = GameObject.Find ("interestingFuncNumber").GetComponent<Text> ();
		basic_blks_text = GameObject.Find ("BasicBlocksSelector").GetComponent<Text> ();
		strings_text = GameObject.Find ("AttributeMiddle").GetComponentsInChildren<Text> () [0];
		strings_count_text = GameObject.Find ("stringsNumber").GetComponent<Text> ();
		module_name_text = GameObject.Find ("ModuleName").GetComponent<Text> ();
		func_name_input = GameObject.Find ("longFuncRenameInput").GetComponent<InputField> ();
		func_name_text = GameObject.Find ("LongFuncName").GetComponent<Text> ();
		func_address_text = GameObject.Find ("Address").GetComponent<Text> ();
		func_name_group = GameObject.Find ("LongNamePanel").GetComponent<HorizontalLayoutGroup> ();
		comment_input = GameObject.Find ("NotesInputField").GetComponent<InputField> ();
		mark_input = GameObject.Find ("markInputField").GetComponent<InputField> ();
		marked_scroll_canvas = GameObject.Find ("MarklistContent").GetComponent<Canvas> ();

		InputField.SubmitEvent commentChangeEvent = new InputField.SubmitEvent ();
		commentChangeEvent.AddListener (ChangeComment);
		comment_input.onEndEdit = commentChangeEvent;

		InputField.SubmitEvent functionChangeEvent = new InputField.SubmitEvent ();
		functionChangeEvent.AddListener (ChangeFunctionName);
		func_name_input.onEndEdit = functionChangeEvent;

		InputField.SubmitEvent markChangeEvent = new InputField.SubmitEvent ();
		markChangeEvent.AddListener (ChangeMark);
		mark_input.onEndEdit = markChangeEvent;
	}

	// Use this for initialization
	void Start () {

	}
	
	// Update is called once per frame
	void Update () {

	}
}