/*! 
@file LookInputModule.cs
@author Zoe Hardisty. <www.zoehardistydesign.com>
		<https://github.com/zoebear/Radia/LookInputModule.cs>
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

Allows the interaction with nodes to instatiate the NodeUI menu.

*/
using UnityEngine;
using UnityEngine.EventSystems;
using UnityEngine.UI;
using System.Collections;

public class LookInputModule : BaseInputModule {
	
	public const int kLookId = -3;
	public string submitButtonName = "Fire1";
	public string controlAxisName = "Horizontal";
	private PointerEventData lookData;
	public GameController controller;

	// use screen midpoint as locked pointer location, enabling look location to be the "mouse"
	private PointerEventData GetLookPointerEventData() {
		Vector2 lookPosition;
		lookPosition.x = Screen.width/2;
		lookPosition.y = Screen.height/2;
		if (lookData == null) {
			lookData = new PointerEventData(eventSystem);
		}
		lookData.Reset();
		lookData.delta = Vector2.zero;
		lookData.position = lookPosition;
		lookData.scrollDelta = Vector2.zero;
		eventSystem.RaycastAll(lookData, m_RaycastResultCache);
		lookData.pointerCurrentRaycast = FindFirstRaycast(m_RaycastResultCache);
		m_RaycastResultCache.Clear();
		return lookData;
	}
	
	private bool SendUpdateEventToSelectedObject() {
		if (eventSystem.currentSelectedGameObject == null)
			return false;
		BaseEventData data = GetBaseEventData ();
		ExecuteEvents.Execute (eventSystem.currentSelectedGameObject, data, ExecuteEvents.updateSelectedHandler);
		return data.used;
	}
	
	public override void Process() {
		// send update events if there is a selected object - this is important for InputField to receive keyboard events
		SendUpdateEventToSelectedObject();
		PointerEventData lookData = GetLookPointerEventData();
		// use built-in enter/exit highlight handler
		HandlePointerExitAndEnter(lookData,lookData.pointerCurrentRaycast.gameObject);
		if (Input.GetKeyDown (KeyCode.Space) && controller.InputActive()) {
			eventSystem.SetSelectedGameObject(null);
			if (lookData.pointerCurrentRaycast.gameObject != null) {
				controller.SelectFunction(lookData.pointerCurrentRaycast.gameObject);

				/*GameObject newPressed = ExecuteEvents.ExecuteHierarchy (go, lookData, ExecuteEvents.submitHandler);
				if (newPressed == null) {
					// submit handler not found, try select handler instead
					newPressed = ExecuteEvents.ExecuteHierarchy (go, lookData, ExecuteEvents.selectHandler);
				}
				if (newPressed != null) {
					eventSystem.SetSelectedGameObject(newPressed);
				}*/
			}
		}
		/*
		if (eventSystem.currentSelectedGameObject && controlAxisName != null && controlAxisName != "") {
			float newVal = Input.GetAxis (controlAxisName);
			if (newVal > 0.01f || newVal < -0.01f) {
				AxisEventData axisData = GetAxisEventData(newVal,0.0f,0.0f);
				ExecuteEvents.Execute(eventSystem.currentSelectedGameObject, axisData, ExecuteEvents.moveHandler);
			}
		}*/
	}   
}